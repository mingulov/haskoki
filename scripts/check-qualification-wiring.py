#!/usr/bin/env python3
"""V4b qualification-lane wiring gate (build-free, stdlib only).

Validates the behavioral lane from the verification plan (V4b),
which builds on the merged V4a lane: the native behavioral matrix
workflow, the driver inventory it relies on (V1 repair, unchanged),
the V4 probe-to-driver ownership it executes (unchanged), and the
matrix cell-to-driver-to-probe wiring the new legs add.

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
  needs the static-gates, toolchain, and proxy-pair jobs, the
  toolchain/proxy-pair jobs need the static-gates job, and the
  report job needs the qualify job.
* QW-LANE-TIMEOUT: every job sets `timeout-minutes`.
* QW-LANE-ARTIFACT: every job uploads an artifact and carries an
  `if: always()` step so partial failure evidence survives a failing run.
* QW-LANE-JOBS: exactly the five V4b jobs exist (static-gates,
  toolchain, proxy-pair, qualify, report): no silent extra leg and
  no dropped one.
* QW-LANE-RUNNER: every job, `qualify` included, runs on the
  GitHub-hosted `ubuntu-latest` label (ruling 1: hosted x86_64
  Linux counts as native behavioral evidence; no self-hosted
  registration, no other label).
* QW-LANE-CONCURRENCY: the concurrency group includes the event
  name, so the weekly schedule never cancels a dispatch run.
* QW-LANE-MATRIX: every V4b matrix cell owns one table row in
  the qualify job carrying its driver and (for tuned legs) its
  selecting environment on that same row: consumer
  default/width/pin-rotate/aging/async reroute/parallel-seed/
  fairness-sweep/hint cells, sim default/thread-reuse/socket-quiet
  cells, finalize default/finalize-wait cells, and the mutexes,
  async-attached, async-detached (+socket), and ossl4 baseline
  cells.
* QW-LANE-EXECUTE: the qualify job executes the matrix drivers
  through a docker-run invocation naming scripts/$driver with the
  forwarded selectors on that same invocation (a row table without
  the execution line, or an invocation that drops the transport,
  would pass MATRIX while running defaults or nothing).
* QW-LANE-LAYOUT: the qualify evidence upload lists runner-temp
  paths only: every receipt stages under the one evidence root,
  never as a bare checkout file beside it (mixed roots nest
  unpredictably in the archive and the report would read the
  wrong layout).
* QW-LANE-FALLBACK: the qualify job keeps the build-only V1
  manifest as a fallback behind an explicit runtime
  classification step (behavioral vs build-only mode): a runner
  that cannot run the matrix still produces classified build
  evidence, never a silent skip, but a build-only run FAILS the
  job as "incomplete: behavioral prerequisites unmet" (ruling 2):
  a step conditioned on the buildonly mode must exit 1, with no
  exit 0 and no continue-on-error. The evidence upload still runs.
* QW-LANE-STATIC: static-gates validates the requested revision
  first (40-hex and HEAD == requested, else "revision must be a
  full SHA"); it also runs this gate's self-test
  plus the build-free driver negative controls (a bogus leg hint
  and a bogus width hint must fail fast), so new wiring ships
  with executed guards.
* QW-MTX-*: the matrix legs are honored end to end, not merely
  named: the consumer driver implements the scenario filter and
  the width passthrough, the sim/async-detached drivers implement
  CPU-socket pinning through taskset, and the C probes read every
  selecting variable the matrix sets.

Run on HOST python3 from anywhere:
  python3 scripts/check-qualification-wiring.py
Self-test (durable negative controls, wired into the CI static step):
  python3 scripts/check-qualification-wiring.py --self-test
runs the positive control (the real tree must pass) plus one
must-fail mutation per required driver owner (including the nested
onboarding driver and the previously unowned finalize-wait probe),
comment-out controls proving comment mentions are not ownership,
execution-omission controls proving guard-only mentions are not
ownership either, inventory drift/duplicate/role mutations, one
must-fail mutation per lane rule (triggers, permissions, build-only
surface, pins, setup gating, timeouts, artifacts, job set, native
label, matrix cells, execution line, upload layout, fallback
classification, static guards), and one must-fail mutation per
matrix leg (scenario filter, width passthrough, pinning modes,
and every probe-side selector).

Receipt verifier (judges a real run, build-free):
  python3 scripts/check-qualification-wiring.py --verify-matrix DIR --expect-sha SHA
* QW-RCPT-MISSING/SHAPE: matrix.json, classification.json and the raw
  cell-results.txt exist and carry sha, requested_revision, runner.
* QW-RCPT-DUPLICATE/CELLS: exact MATRIX_CELLS set; duplicates rejected
  on the raw list before any dict; no absent or unknown cell.
* QW-RCPT-MODE/RESULT/SHA: behavioral in both receipts, 25/25 pass,
  sha equals --expect-sha.
* QW-LANE-VERIFY: qualify ends with the verifier, report runs it
  without swallowing failure (no `|| true`, no continue-on-error), the
  expected sha is the requested revision (REQUESTED_REVISION env =
  dispatch input or github.sha), never the checkout's own HEAD, and
  the builder emits the identity fields. The verifier also rejects
  requested_revision != sha, a pass cell with rc != 0, and cells
  lacking rc or duration_s.
* QW-LANE-OWNERSHIP: the qualify job runs scripts/test-ownership-matrix.sh
  through docker run with the exact SHA and a receipt directory under
  the evidence root, on `if: always()` (both verdicts recorded) and
  never swallowed.
* QW-LANE-OWNERSHIP also pins the receipt directory under
  $RUNNER_TEMP/qualify-evidence and the always-run upload of that
  whole root (so the ownership receipts are uploaded).
* QW-LANE-VERIFY also rejects job-level `continue-on-error` on
  every job; QW-LANE-STATIC anchors on the SHA gate (first step
  after checkout, exits nonzero); QW-LANE-CONCURRENCY pins the
  schedule-only cancel-in-progress expression.
* QW-LANE-GATE (ruling 7): qualify keeps `needs: toolchain`, and the
  loaded image's id must equal the toolchain job's recorded
  builder_image_id ("toolchain image id mismatch" guard).
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
OWNERSHIP_DRIVER = "test-ownership-matrix.sh"
NESTED_CHILD = "test-demo-onboarding.sh"
NESTED_PARENT = "test-demo-image.sh"

SETUP_JOBS = ("static-gates", "toolchain", "proxy-pair")
QUALIFY_JOB = "qualify"
REPORT_JOB = "report"
ALL_JOBS = ("static-gates", "toolchain", "proxy-pair", "qualify", "report")
RUNNER_LABEL = "ubuntu-latest"

# (cell, driver script, required env tokens). Every cell owns one
# table row starting with "name|driver|env": the driver and EVERY
# token must sit on that same row, so a row that drops or retunes
# any assignment fails even when another row still carries a
# related token (a selector-less row would silently run the
# default instead of the leg; a retuned row would mislabel it).
_MT = "HASKOKI_QUAL_ONLY=consumer_multithread"
_AR = "HASKOKI_QUAL_ONLY=async_routed"
MATRIX_CELLS = [
    ("consumers/default", "test-consumers.sh", ()),
    ("consumers/width-64", "test-consumers.sh", ("HASKOKI_WIDTH_LEG=64",)),
    ("pin-rotate", "test-consumers.sh", (_MT, "HASKOKI_MT_PIN_ROTATE=1")),
    ("aging", "test-consumers.sh", (_MT, "HASKOKI_MT_AGING=1")),
    ("async-reroute", "test-consumers.sh", (_AR, "HASKOKI_ASYNC_REROUTE=1")),
    ("async-parallel-seed", "test-consumers.sh",
     (_AR, "HASKOKI_ASYNC_PARALLEL_SEED=8")),
    ("serial-fairness", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=1", "HASKOKI_MT_FAIR=1")),
    ("fairness-1-app", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=1", "HASKOKI_MT_MUTEX=1", "HASKOKI_MT_FAIR=1")),
    ("fairness-2-null", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=2", "HASKOKI_MT_FAIR=1")),
    ("fairness-2-app", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=2", "HASKOKI_MT_MUTEX=1", "HASKOKI_MT_FAIR=1")),
    ("fairness-4-null", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=4", "HASKOKI_MT_FAIR=1")),
    ("mutex-fairness", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=4", "HASKOKI_MT_MUTEX=1", "HASKOKI_MT_FAIR=1")),
    ("fairness-8-null", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=8", "HASKOKI_MT_FAIR=1")),
    ("fairness-8-app", "test-consumers.sh",
     (_MT, "HASKOKI_MT_N=8", "HASKOKI_MT_MUTEX=1", "HASKOKI_MT_FAIR=1")),
    ("hint-strictness", "test-consumers.sh", (_MT, "HASKOKI_MT_HINT_STRICT=1")),
    ("sim/default", "test-sim-threaded.sh", ()),
    ("thread-reuse", "test-sim-threaded.sh",
     ("HASKOKI_SIM_WAVES=3", "HASKOKI_SIM_ITERS=5000", "HASKOKI_SIM_M=20")),
    ("socket-quiet", "test-sim-threaded.sh", ("HASKOKI_SOCKET_CPU=0",)),
    ("finalize/default", "test-finalize-race.sh", ()),
    ("finalize-wait", "test-finalize-race.sh", ("HASKOKI_FINALIZE_WAIT_CYCLES=200",)),
    ("mutexes/default", "test-c-mutexes.sh", ()),
    ("async-attached/default", "test-async-attached.sh", ()),
    ("async-detached/default", "test-async-detached.sh", ()),
    ("async-socket", "test-async-detached.sh", ("HASKOKI_SOCKET_CPU=0",)),
    ("ossl4/default", "test-ossl4-bounds.sh", ()),
]

# (probe, selecting variable): every matrix selector the qualify
# job sets must be read by its probe. Presence in the probe file
# (code or declaration comment) pins the contract; the native run
# proves the behavior.
MATRIX_PROBES = [
    ("tests/c/consumer_multithread.c", "HASKOKI_MT_PIN_ROTATE"),
    ("tests/c/consumer_multithread.c", "HASKOKI_MT_AGING"),
    ("tests/c/consumer_multithread.c", "HASKOKI_MT_MUTEX"),
    ("tests/c/consumer_multithread.c", "HASKOKI_MT_FAIR"),
    ("tests/c/consumer_multithread.c", "HASKOKI_MT_HINT_STRICT"),
    ("tests/c/consumer_multithread.c", "HASKOKI_WIDTH_LEG"),
    ("tests/c/async_routed.c", "HASKOKI_ASYNC_REROUTE"),
    ("tests/c/async_routed.c", "HASKOKI_ASYNC_PARALLEL_SEED"),
    ("tests/c/sim_threaded.c", "HASKOKI_SIM_WAVES"),
    ("tests/c/mutexes.c", "HASKOKI_WIDTH_LEG"),
]

# Drivers honoring CPU-socket pinning for the socket-quiet and
# async-socket cells. (The proxy pair is a transport the async
# proofs provably cannot cross — parity DIRECT-ONLY issues 24/25 —
# so the socket legs pin scheduling instead of proxying.)
PIN_DRIVERS = ("scripts/test-sim-threaded.sh", "scripts/test-async-detached.sh")

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
        if name == OWNERSHIP_DRIVER and role != "qualification":
            _add(failures, "QW-INV-ROLE",
                 f"{name}: must be role 'qualification' (outside the 19-step manifest), got {role!r}")
        if role not in ("container", "host", "nested", "qualification"):
            _add(failures, "QW-INV-ROLE", f"{name}: bad role: {role!r}")
        elif role in ("container", "host", "qualification"):
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
    if set(blocks) != set(ALL_JOBS):
        _add(failures, "QW-LANE-JOBS",
             f"lane needs exactly the five V4b jobs, got: {sorted(blocks)}")
    for name, block in blocks.items():
        match = re.search(r"(?m)^    runs-on:\s*(.+?)\s*$", block)
        if not match or match.group(1) != RUNNER_LABEL:
            _add(failures, "QW-LANE-RUNNER",
                 f"job {name} must run on {RUNNER_LABEL}, got "
                 f"{match.group(1) if match else 'no runs-on'}")
    concurrency = _section(text, "concurrency", 0) or ""
    group_line = next((ln for ln in concurrency.splitlines()
                       if ln.strip().startswith("group:")), "")
    if "github.event_name" not in group_line:
        _add(failures, "QW-LANE-CONCURRENCY",
             "concurrency group must include github.event_name (schedule must not cancel dispatch)")
    cancel_line = next((ln.strip() for ln in concurrency.splitlines()
                        if ln.strip().startswith("cancel-in-progress:")), "")
    if cancel_line != "cancel-in-progress: ${{ github.event_name == 'schedule' }}":
        _add(failures, "QW-LANE-CONCURRENCY",
             "cancel-in-progress must be exactly the schedule-only expression "
             "(a dispatch run must never be cancelled): got "
             f"{cancel_line or 'no cancel-in-progress'!r}")
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
        if "toolchain image id mismatch" not in blocks[QUALIFY_JOB] \
                or "builder_image_id" not in blocks[QUALIFY_JOB]:
            _add(failures, "QW-LANE-GATE",
                 f"{QUALIFY_JOB} must verify the loaded image id against the "
                 "toolchain job's recorded builder_image_id")
        rows = [line.strip() for line in blocks[QUALIFY_JOB].splitlines()
                if "|" in line and not line.strip().startswith("#")]
        for cell, driver, tokens in MATRIX_CELLS:
            row = next((r for r in rows if r.startswith(cell + "|")), None)
            if row is None:
                _add(failures, "QW-LANE-MATRIX",
                     f"matrix cell {cell} owns no table row in {QUALIFY_JOB}")
                continue
            if driver not in row:
                _add(failures, "QW-LANE-MATRIX",
                     f"matrix cell {cell} names no driver {driver} on its row")
            for token in tokens:
                if token not in row:
                    _add(failures, "QW-LANE-MATRIX",
                         f"matrix cell {cell} drops {token} from its row")
        executed = any("docker run" in line and "scripts/$driver" in line
                       and "$ENV_ARGS" in line
                       for line in _code_lines(blocks[QUALIFY_JOB]))
        if not executed:
            _add(failures, "QW-LANE-EXECUTE",
                 f"{QUALIFY_JOB} executes no matrix driver through "
                 "docker run with forwarded selectors")
        qualify = blocks[QUALIFY_JOB]
        up = qualify.find("Upload qualification evidence")
        if up < 0:
            _add(failures, "QW-LANE-LAYOUT", f"{QUALIFY_JOB} has no evidence upload step")
        else:
            lines = qualify[up:].splitlines()
            anchor = next((i for i, line in enumerate(lines)
                           if line.strip() == "path: |"), None)
            if anchor is None:
                _add(failures, "QW-LANE-LAYOUT", f"{QUALIFY_JOB} upload lists no paths")
            else:
                for line in lines[anchor + 1:]:
                    if not line.startswith("            ") or not line.strip():
                        break
                    if "runner.temp" not in line:
                        _add(failures, "QW-LANE-LAYOUT",
                             "qualify upload mixes a non-runner-temp path: "
                             f"{line.strip()[:60]} (receipts must stage under one root)")
        if "classif" not in qualify:
            _add(failures, "QW-LANE-FALLBACK",
                 f"{QUALIFY_JOB} has no runtime classification step")
        if "behavioral" not in qualify or "buildonly" not in qualify:
            _add(failures, "QW-LANE-FALLBACK",
                 f"{QUALIFY_JOB} must select a behavioral vs buildonly mode")
        if "release-evidence.sh" not in qualify:
            _add(failures, "QW-LANE-FALLBACK",
                 f"{QUALIFY_JOB} keeps no build-only manifest fallback")
        incomplete = [st for st in re.split(r"(?m)^      - name:", qualify)
                      if "incomplete: behavioral prerequisites unmet" in st]
        if len(incomplete) != 1:
            _add(failures, "QW-LANE-FALLBACK",
                 f"{QUALIFY_JOB} needs one step failing a build-only run as "
                 "'incomplete: behavioral prerequisites unmet'")
        else:
            step = incomplete[0]
            code = [ln.split("#", 1)[0] for ln in step.splitlines()]
            if "mode == 'buildonly'" not in step:
                _add(failures, "QW-LANE-FALLBACK",
                     "the incomplete step must be conditioned on the buildonly mode")
            if not any(re.fullmatch(r"\s*exit 1\s*", ln) for ln in code) \
                    or any(re.search(r"\bexit 0\b", ln) for ln in code) \
                    or "continue-on-error" in step:
                _add(failures, "QW-LANE-FALLBACK",
                     "a build-only run must exit 1 (no exit 0, no continue-on-error)")
    if REPORT_JOB not in blocks:
        _add(failures, "QW-LANE-GATE", f"missing matrix job: {REPORT_JOB}")
    else:
        needs = _needs_of(blocks[REPORT_JOB])
        if needs is None or QUALIFY_JOB not in needs:
            _add(failures, "QW-LANE-GATE",
                 f"{REPORT_JOB} must need {QUALIFY_JOB} (matrix renders qualify evidence)")
    for job, jblock in blocks.items():
        if re.search(r"(?m)^    continue-on-error:", jblock):
            _add(failures, "QW-LANE-VERIFY",
                 f"{job}: job-level continue-on-error would let a failed job report success")
    for job in (QUALIFY_JOB, REPORT_JOB):
        if job not in blocks:
            continue
        steps = re.split(r"(?m)^      - name:", blocks[job])
        last = steps[-1] if len(steps) > 1 else ""
        if job == QUALIFY_JOB and "--verify-matrix" not in last:
            _add(failures, "QW-LANE-VERIFY",
                 f"{job}: the last step must run check-qualification-wiring.py --verify-matrix")
        verify = [ln for ln in blocks[job].splitlines()
                  if "--verify-matrix" in ln or "--expect-sha" in ln]
        if not any("--verify-matrix" in ln for ln in verify) or \
                "--expect-sha" not in blocks[job].split("--verify-matrix", 1)[-1]:
            _add(failures, "QW-LANE-VERIFY",
                 f"{job}: no --verify-matrix ... --expect-sha invocation")
        elif any("|| true" in ln or "|| :" in ln for ln in verify):
            _add(failures, "QW-LANE-VERIFY", f"{job}: verifier failure is swallowed")
        vsteps = [st for st in re.split(r"(?m)^      - name:", blocks[job])
                  if "--verify-matrix" in st]
        if any("continue-on-error" in st for st in vsteps):
            _add(failures, "QW-LANE-VERIFY", f"{job}: verify step has continue-on-error")
        if '--expect-sha "$REQUESTED_REVISION"' not in blocks[job] \
                or "REQUESTED_REVISION: ${{ inputs.revision || github.sha }}" not in blocks[job]:
            _add(failures, "QW-LANE-VERIFY",
                 f"{job}: expected sha must be the requested revision "
                 "(REQUESTED_REVISION = inputs.revision || github.sha), not the checkout HEAD")
        elif "--expect-sha" in blocks[job] and re.search(r"--expect-sha[^\n]*rev-parse", blocks[job]):
            _add(failures, "QW-LANE-VERIFY", f"{job}: expected sha derived from the checkout")
    for job in (QUALIFY_JOB, REPORT_JOB):
        if job not in blocks:
            continue
        osteps = [st for st in re.split(r"(?m)^      - name:", blocks[job])
                  if "--verify-ownership" in "\n".join(_code_lines(st))]
        if len(osteps) != 1:
            _add(failures, "QW-LANE-OWNVERIFY",
                 f"{job}: need exactly one --verify-ownership step (found {len(osteps)})")
            continue
        code = "\n".join(_code_lines(osteps[0]))
        if "--expect-sha" not in code or '--expect-sha "$REQUESTED_REVISION"' not in code \
                or "REQUESTED_REVISION: ${{ inputs.revision || github.sha }}" not in osteps[0]:
            _add(failures, "QW-LANE-OWNVERIFY",
                 f"{job}: ownership verifier must check the requested revision "
                 "(REQUESTED_REVISION = inputs.revision || github.sha)")
        if "|| true" in code or "|| :" in code or "continue-on-error" in osteps[0]:
            _add(failures, "QW-LANE-OWNVERIFY", f"{job}: ownership verifier failure is swallowed")
        if not re.search(r"(?m)^        if: always\(\)\s*$", osteps[0]):
            _add(failures, "QW-LANE-OWNVERIFY", f"{job}: ownership verifier must run on if: always()")
        want = ("$RUNNER_TEMP/qualify-evidence/ownership" if job == QUALIFY_JOB
                else "evidence-in/qualify-evidence/ownership")
        if want not in code:
            _add(failures, "QW-LANE-OWNVERIFY", f"{job}: ownership verifier must read {want}")
    if QUALIFY_JOB in blocks:
        for token in ("requested_revision", "image_id", "nproc", "duration_s", "RECEIPT_SHA"):
            if token not in blocks[QUALIFY_JOB]:
                _add(failures, "QW-LANE-VERIFY",
                     f"{QUALIFY_JOB}: matrix.json builder does not emit {token}")
    if "static-gates" in blocks:
        static = blocks["static-gates"]
        if "check-qualification-wiring.py --self-test" not in static:
            _add(failures, "QW-LANE-STATIC",
                 "static-gates must run this gate's self-test")
        if "revision must be a full SHA" not in static or "{40}" not in static \
                or "git rev-parse HEAD" not in static:
            _add(failures, "QW-LANE-STATIC",
                 "static-gates must check the requested revision is a full SHA equal to HEAD")
        ssteps = re.split(r"(?m)^      - name:", static)[1:]
        gate_idx = next((i for i, st in enumerate(ssteps)
                         if "revision must be a full SHA" in st), None)
        if gate_idx is None:
            pass  # reported by the substring rule above
        else:
            if gate_idx != 1 or "actions/checkout@" not in ssteps[0]:
                _add(failures, "QW-LANE-STATIC",
                     "the full-SHA gate must be the first step after checkout "
                     f"(found at step {gate_idx + 1})")
            gate_lines = _code_lines(ssteps[gate_idx])
            if not any(re.search(r"\bexit\s+[1-9]", ln) for ln in gate_lines):
                _add(failures, "QW-LANE-STATIC",
                     "the full-SHA gate must exit nonzero on a mismatch")
            if any("|| true" in ln or "|| :" in ln for ln in gate_lines):
                _add(failures, "QW-LANE-STATIC", "the full-SHA gate failure is swallowed")
        if "HASKOKI_QUAL_ONLY=bogus" not in static:
            _add(failures, "QW-LANE-STATIC",
                 "static-gates must run the bogus-hint negative control")
    for setup in ("toolchain", "proxy-pair"):
        if setup in blocks:
            needs = _needs_of(blocks[setup])
            if needs is None or "static-gates" not in needs:
                _add(failures, "QW-LANE-GATE",
                     f"{setup} must need static-gates (setup failures gate execution)")
    if QUALIFY_JOB in blocks:
        osteps = [st for st in re.split(r"(?m)^      - name:", blocks[QUALIFY_JOB])
                  if "scripts/test-ownership-matrix.sh" in "\n".join(_code_lines(st))]
        if len(osteps) != 1:
            _add(failures, "QW-LANE-OWNERSHIP",
                 f"{QUALIFY_JOB} must run scripts/test-ownership-matrix.sh in exactly one step "
                 f"(found {len(osteps)})")
        else:
            ost = osteps[0]
            code = "\n".join(_code_lines(ost))
            if "docker run" not in code:
                _add(failures, "QW-LANE-OWNERSHIP", "ownership driver must run through docker run")
            if "HASKOKI_OWN_SHA" not in code or "git rev-parse HEAD" not in code:
                _add(failures, "QW-LANE-OWNERSHIP", "ownership driver must receive the exact SHA")
            if "HASKOKI_OWN_RECEIPTS" not in code or "qualify-evidence" not in code:
                _add(failures, "QW-LANE-OWNERSHIP",
                     "ownership receipts must land under the qualify evidence root")
            if 'OWN_DIR="$RUNNER_TEMP/qualify-evidence/ownership"' not in code \
                    or '-v "$OWN_DIR:/ownership"' not in code:
                _add(failures, "QW-LANE-OWNERSHIP",
                     "ownership receipts (OWN_DIR) must be a directory under "
                     "$RUNNER_TEMP/qualify-evidence mounted at /ownership")
            qj = blocks[QUALIFY_JOB]
            qup = qj.find("Upload qualification evidence")
            ustep = qj[qup:].split("\n      - name:")[0] if qup >= 0 else ""
            if not re.search(r"(?m)^        if: always\(\)", ustep) or \
                    "${{ runner.temp }}/qualify-evidence/" not in \
                    [ln.strip() for ln in ustep.splitlines()]:
                _add(failures, "QW-LANE-OWNERSHIP",
                     "the always-run evidence upload must cover the whole "
                     "${{ runner.temp }}/qualify-evidence/ root (ownership receipts)")
            if not re.search(r"(?m)^        if: always\(\)", ost):
                _add(failures, "QW-LANE-OWNERSHIP",
                     "ownership step must run on if: always() (record both verdicts)")
            if "continue-on-error" in ost or "|| true" in code or "|| :" in code:
                _add(failures, "QW-LANE-OWNERSHIP", "ownership failure is swallowed")
    for name, block in blocks.items():
        if not re.search(r"(?m)^    timeout-minutes:\s*\d+\s*$", block):
            _add(failures, "QW-LANE-TIMEOUT", f"job {name} has no timeout-minutes")
        if "actions/upload-artifact@" not in block:
            _add(failures, "QW-LANE-ARTIFACT", f"job {name} uploads no artifact")
        if "if: always()" not in block:
            _add(failures, "QW-LANE-ARTIFACT",
                 f"job {name} has no if: always() step (partial failure evidence)")


def check_matrix_wiring(root, failures):
    """QW-MTX-*: every matrix selector is honored end to end: the
    consumer driver implements the scenario filter and the width
    passthrough on executable lines, the pinned drivers implement
    CPU-socket pinning through taskset on executable lines, and
    every probe reads its selectors (a getenv-family fetch or a
    preprocessor conditional — a comment mention is not a read)."""
    try:
        consumers = (root / "scripts/test-consumers.sh").read_text()
    except OSError:
        _add(failures, "QW-MTX-DRIVER", "missing driver: scripts/test-consumers.sh")
        consumers = None
    if consumers is not None:
        code = _code_lines(consumers)
        if not any("HASKOKI_QUAL_ONLY" in line for line in code):
            _add(failures, "QW-MTX-FILTER",
                 "test-consumers.sh honors no HASKOKI_QUAL_ONLY scenario filter")
        if not any("HASKOKI_WIDTH_LEG" in line for line in code):
            _add(failures, "QW-MTX-WIDTH",
                 "test-consumers.sh passes no HASKOKI_WIDTH_LEG width selector")
    try:
        mutexes = (root / "scripts/test-c-mutexes.sh").read_text()
    except OSError:
        _add(failures, "QW-MTX-DRIVER", "missing driver: scripts/test-c-mutexes.sh")
        mutexes = None
    if mutexes is not None:
        if not any("HASKOKI_WIDTH_LEG" in line for line in _code_lines(mutexes)):
            _add(failures, "QW-MTX-WIDTH",
                 "test-c-mutexes.sh passes no HASKOKI_WIDTH_LEG width selector")
    for driver in PIN_DRIVERS:
        try:
            text = (root / driver).read_text()
        except OSError:
            _add(failures, "QW-MTX-DRIVER", f"missing driver: {driver}")
            continue
        code = _code_lines(text)
        if not any("HASKOKI_SOCKET_CPU" in line for line in code):
            _add(failures, "QW-MTX-PIN", f"{driver} honors no HASKOKI_SOCKET_CPU pinning")
        if not any("taskset" in line for line in code):
            _add(failures, "QW-MTX-PIN", f"{driver} pins through no taskset invocation")
    for probe, var in MATRIX_PROBES:
        try:
            text = (root / probe).read_text()
        except OSError:
            _add(failures, "QW-MTX-PROBE", f"missing probe file: {probe}")
            continue
        # A read is the variable on a line that fetches it: a
        # direct getenv, a preprocessor conditional on the
        # compile-time macro, or one of the file-local read
        # wrappers (each calls getenv unconditionally).
        read = any(var in line and ("getenv" in line or "#if" in line
                                    or "env_enabled" in line or "env_long" in line)
                   for line in text.splitlines())
        if not read:
            _add(failures, "QW-MTX-PROBE", f"{probe} never reads {var}")


def run_all(root):
    """Run every rule against the tree at root; return failure strings."""
    failures = _failures()
    by_name = check_inventory(root, failures)
    check_nested_onboarding(by_name, failures)
    check_nested_invocation(root, failures)
    check_owners(root, failures)
    check_lane(root, failures)
    check_matrix_wiring(root, failures)
    check_ownership_table(root, failures)
    return failures


# ------------------------------------------------------------------
# QW-RCPT-*: matrix receipt verifier (--verify-matrix DIR --expect-sha SHA).
# ------------------------------------------------------------------

def _dups(names):
    seen, dup = set(), []
    for name in names:
        if name in seen and name not in dup:
            dup.append(name)
        seen.add(name)
    return dup


def _check_names(source, names, expected, failures):
    """Duplicates are rejected on the raw list before any dict/set is built."""
    for name in _dups(names):
        _add(failures, "QW-RCPT-DUPLICATE", f"{source}: cell {name!r} appears more than once")
    got = set(names)
    for name in sorted(expected - got):
        _add(failures, "QW-RCPT-CELLS", f"{source}: expected cell {name!r} absent")
    for name in sorted(got - expected):
        _add(failures, "QW-RCPT-CELLS", f"{source}: unknown cell {name!r}")


def _load_json(path, failures):
    try:
        return json.loads(path.read_text())
    except OSError:
        _add(failures, "QW-RCPT-MISSING", f"missing or unreadable {path.name}")
    except ValueError as exc:
        _add(failures, "QW-RCPT-SHAPE", f"{path.name} is not valid JSON: {exc}")
    return None


def verify_matrix(receipt_dir, expect_sha):
    """Return QW-RCPT failure strings for the receipt directory.

    Judges a real run: exact expected cell set (MATRIX_CELLS), raw
    cell-results.txt lines parsed as a list so duplicates are rejected
    before any dict, behavioral mode in both matrix.json and
    classification.json, every cell pass, and sha == expect_sha.
    """
    receipt_dir = Path(receipt_dir)
    failures = _failures()
    expected = {cell for cell, _driver, _env in MATRIX_CELLS}
    if not re.fullmatch(r"[0-9a-f]{40}", expect_sha or ""):
        _add(failures, "QW-RCPT-SHA", f"expected sha is not 40 lowercase hex: {expect_sha!r}")

    classification = _load_json(receipt_dir / "classification.json", failures)
    if classification is not None:
        mode = classification.get("mode") if isinstance(classification, dict) else None
        if mode != "behavioral":
            _add(failures, "QW-RCPT-MODE", f"classification.json mode is {mode!r}, need 'behavioral'")

    matrix = _load_json(receipt_dir / "matrix.json", failures)
    if isinstance(matrix, dict):
        if matrix.get("mode") != "behavioral":
            _add(failures, "QW-RCPT-MODE", f"matrix.json mode is {matrix.get('mode')!r}, need 'behavioral'")
        if matrix.get("sha") != expect_sha:
            _add(failures, "QW-RCPT-SHA", f"matrix.json sha {matrix.get('sha')!r} != expected {expect_sha!r}")
        if not matrix.get("requested_revision"):
            _add(failures, "QW-RCPT-SHAPE", "matrix.json lacks requested_revision")
        elif matrix.get("requested_revision") != matrix.get("sha"):
            _add(failures, "QW-RCPT-SHA",
                 f"requested_revision {matrix.get('requested_revision')!r} != "
                 f"checked-out sha {matrix.get('sha')!r}")
        runner = matrix.get("runner")
        if not isinstance(runner, dict) or not all(runner.get(k) for k in ("os", "nproc", "image_id")):
            _add(failures, "QW-RCPT-SHAPE", "matrix.json runner needs os, nproc and image_id")
        cells = matrix.get("cells")
        if not isinstance(cells, list) or not all(isinstance(c, dict) for c in cells):
            _add(failures, "QW-RCPT-SHAPE", "matrix.json cells must be a list of objects")
        else:
            _check_names("matrix.json", [str(c.get("name")) for c in cells], expected, failures)
            bad = [str(c.get("name")) for c in cells if c.get("result") != "pass"]
            for name in bad:
                _add(failures, "QW-RCPT-RESULT", f"matrix.json: cell {name!r} did not pass")
            for cell in cells:
                rc, dur = cell.get("rc"), cell.get("duration_s")
                if isinstance(rc, bool) or not isinstance(rc, int):
                    _add(failures, "QW-RCPT-SHAPE", f"matrix.json: cell {cell.get('name')!r} lacks integer rc")
                elif cell.get("result") == "pass" and rc != 0:
                    _add(failures, "QW-RCPT-RESULT",
                         f"matrix.json: cell {cell.get('name')!r} passes with rc={rc}")
                if isinstance(dur, bool) or not isinstance(dur, (int, float)) or dur < 0:
                    _add(failures, "QW-RCPT-SHAPE",
                         f"matrix.json: cell {cell.get('name')!r} lacks duration_s")
            passed = len(cells) - len(bad)
            if passed != len(expected):
                _add(failures, "QW-RCPT-RESULT", f"matrix.json: {passed}/{len(expected)} cells pass")
        if matrix.get("failures"):
            _add(failures, "QW-RCPT-RESULT", f"matrix.json lists failures: {matrix.get('failures')}")
    elif matrix is not None:
        _add(failures, "QW-RCPT-SHAPE", "matrix.json must be an object")

    try:
        raw_text = (receipt_dir / "cell-results.txt").read_text()
    except OSError:
        _add(failures, "QW-RCPT-MISSING", "missing or unreadable cell-results.txt")
    else:
        names, results = [], []
        for number, line in enumerate(raw_text.splitlines(), 1):
            if not line.strip():
                continue
            parts = line.strip().rsplit(" ", 1)
            if len(parts) != 2 or parts[1] not in ("pass", "FAIL"):
                _add(failures, "QW-RCPT-SHAPE", f"cell-results.txt:{number}: unparseable line {line!r}")
                continue
            names.append(parts[0])
            results.append(parts[1])
        _check_names("cell-results.txt", names, expected, failures)
        for name, result in zip(names, results):
            if result != "pass":
                _add(failures, "QW-RCPT-RESULT", f"cell-results.txt: cell {name!r} is {result}")
    return failures


# ------------------------------------------------------------------
# QW-OWN-*: ownership receipt verifier (--verify-ownership DIR --expect-sha SHA).
# The expected case set is independent of the driver's own CASE_TABLE:
# the driver's PLANNED count is derived from that table, so a dropped or
# renamed row would otherwise shrink the obligation silently. Editing a
# row therefore means editing this list too (QW-OWN-TABLE pins the two).
# ------------------------------------------------------------------

OWNERSHIP_RTS = (1, 2, 4)
# (case id, minimum listed tests, counters required)
OWNERSHIP_CASES = [
    ("m1-native-transfers", 11, True),
    ("m1-openssl4-engine", 70, False),
    ("m1-acquisition-hooks", 17, False),
    ("m2-lease-protocol", 6, False),
    ("m2-lifetime-gate", 12, True),
    ("m3-handle-registry", 11, True),
    ("m3-ffi-acquisition", 23, True),
    ("m3-async-engine", 25, True),
    ("m4-store-contract", 123, False),
    ("m4-multi-session", 34, False),
    ("m5-attachment-claims", 5, True),
    ("m5-detached-jobs", 35, True),
    ("m5-scoped-detach-leases", 9, False),
    ("m6-two-contexts-distinct-ids", 1, False),
    ("m6-store-wide-counter", 1, False),
    ("m7-attached-async", 37, True),
    ("m7-retirement", 5, False),
]
# Appended by their own WPs; the driver lists them but never counts them.
OWNERSHIP_PENDING = ["wp07-pending", "wp08-pending", "wp09-pending"]
OWNERSHIP_RECEIPT_RE = re.compile(r"^(?P<case>.+)\.N(?P<n>[0-9]+)\.json$")


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def verify_ownership(receipt_dir, expect_sha):
    """Return QW-OWN failure strings for an ownership receipt directory.

    Post-hoc and driver-independent: every expected (case, RTS) receipt
    exists exactly once, nothing unexpected exists (renamed rows, N3,
    pending rows), every receipt is a pass for the expected sha with
    matching RTS evidence and a listed count at or above the floor, and
    gated cases carry zero-valued counter lines of their own case.
    """
    receipt_dir = Path(receipt_dir)
    failures = _failures()
    if not re.fullmatch(r"[0-9a-f]{40}", expect_sha or ""):
        _add(failures, "QW-OWN-SHA", f"expected sha is not 40 lowercase hex: {expect_sha!r}")
    if not receipt_dir.is_dir():
        _add(failures, "QW-OWN-MISSING", f"ownership receipt directory {receipt_dir} is absent")
        return failures
    expected = {(c, n): (m, g) for c, m, g in OWNERSHIP_CASES for n in OWNERSHIP_RTS}
    found = {}
    for path in sorted(receipt_dir.iterdir()):
        match = OWNERSHIP_RECEIPT_RE.match(path.name)
        if not match:
            continue
        key = (match.group("case"), int(match.group("n")))
        if key not in expected:
            _add(failures, "QW-OWN-UNKNOWN",
                 f"unexpected receipt {path.name} (not in the expected case x RTS set)")
            continue
        found[key] = path
    for case, n in sorted(expected):
        if (case, n) not in found:
            _add(failures, "QW-OWN-MISSING", f"missing receipt {case}.N{n}.json")
    for (case, n), path in sorted(found.items()):
        minimum, gated = expected[(case, n)]
        name = path.name
        try:
            body = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            _add(failures, "QW-OWN-SHAPE", f"{name} is unreadable or not valid JSON: {exc}")
            continue
        if not isinstance(body, dict):
            _add(failures, "QW-OWN-SHAPE", f"{name} must be a JSON object")
            continue
        if body.get("case") != case:
            _add(failures, "QW-OWN-UNKNOWN", f"{name}: case field is {body.get('case')!r}")
        if body.get("sha") != expect_sha:
            _add(failures, "QW-OWN-SHA", f"{name}: sha {body.get('sha')!r} != expected {expect_sha!r}")
        if body.get("rts_n") != n or body.get("using_n") != n:
            _add(failures, "QW-OWN-RTS",
                 f"{name}: rts_n={body.get('rts_n')!r} using_n={body.get('using_n')!r}, need {n}")
        if body.get("status") != "pass" or body.get("rc") != 0 or body.get("reason"):
            _add(failures, "QW-OWN-RESULT",
                 f"{name}: status={body.get('status')!r} rc={body.get('rc')!r} "
                 f"reason={body.get('reason')!r}")
        listed, passed = body.get("listed"), body.get("passed")
        if not _int(listed) or not _int(passed) or listed < minimum or passed != listed:
            _add(failures, "QW-OWN-COUNT",
                 f"{name}: listed={listed!r} passed={passed!r}, need passed == listed >= {minimum}")
        if body.get("counters_required") is not gated:
            _add(failures, "QW-OWN-COUNTERS",
                 f"{name}: counters_required={body.get('counters_required')!r}, need {gated}")
        lines = body.get("counters")
        if not isinstance(lines, list):
            _add(failures, "QW-OWN-SHAPE", f"{name}: counters must be a list")
        elif gated:
            if not lines:
                _add(failures, "QW-OWN-COUNTERS", f"{name}: gated case has no counter lines")
            for line in lines:
                fields = str(line).split()
                head = [f for f in fields if f.startswith("case=")]
                values = [f for f in fields if "=" in f and not f.startswith(("case=", "test="))]
                if head[:1] != [f"case={case}"]:
                    _add(failures, "QW-OWN-COUNTERS", f"{name}: counter line for another case: {line!r}")
                elif any(v.split("=", 1)[1] != "0" for v in values):
                    _add(failures, "QW-OWN-COUNTERS", f"{name}: nonzero counter: {line!r}")
    for pending in OWNERSHIP_PENDING:
        for path in receipt_dir.glob(f"{pending}.N*.json"):
            _add(failures, "QW-OWN-UNKNOWN", f"pending row {pending} has a receipt: {path.name}")

    # index.tsv: one passing row per expected (case, RTS), nothing else.
    try:
        index_text = (receipt_dir / "index.tsv").read_text()
    except OSError:
        _add(failures, "QW-OWN-MISSING", "missing or unreadable index.tsv")
    else:
        rows = [ln.split("\t") for ln in index_text.splitlines()[1:] if ln.strip()]
        keys = []
        for row in rows:
            if len(row) != 7 or not row[1].isdigit():
                _add(failures, "QW-OWN-INDEX", f"index.tsv: unparseable row {row!r}")
                continue
            keys.append((row[0], int(row[1])))
            if row[5] != "pass" or row[4] != "0":
                _add(failures, "QW-OWN-INDEX", f"index.tsv: {row[0]} -N{row[1]} is {row[5]} rc {row[4]}")
        for key in _dups(keys):
            _add(failures, "QW-OWN-INDEX", f"index.tsv: duplicate row for {key[0]} -N{key[1]}")
        got = set(keys)
        for key in sorted(set(expected) - got):
            _add(failures, "QW-OWN-INDEX", f"index.tsv: missing row for {key[0]} -N{key[1]}")
        for key in sorted(got - set(expected)):
            _add(failures, "QW-OWN-INDEX", f"index.tsv: unexpected row for {key[0]} -N{key[1]}")
    return failures


def check_ownership_table(root, failures):
    """QW-OWN-TABLE: the driver's active CASE_TABLE rows equal OWNERSHIP_CASES."""
    path = Path(root) / "scripts" / OWNERSHIP_DRIVER
    try:
        text = path.read_text()
        body = text.split("<<'TABLE'\n", 1)[1].split("\nTABLE\n", 1)[0]
    except (OSError, IndexError):
        _add(failures, "QW-OWN-TABLE", f"cannot read the case table of {OWNERSHIP_DRIVER}")
        return
    rows, pending = [], []
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split("|")
        if len(f) != 6 or not f[3].isdigit():
            _add(failures, "QW-OWN-TABLE", f"malformed case table row: {line[:60]!r}")
            continue
        if f[4] == "pending":
            pending.append(f[0])
        elif f[4] == "active":
            rows.append((f[0], int(f[3]), f[5] != "no"))
        else:
            _add(failures, "QW-OWN-TABLE", f"row {f[0]!r} has status {f[4]!r}")
    for dup in _dups([r[0] for r in rows]):
        _add(failures, "QW-OWN-TABLE", f"duplicate case row {dup!r}")
    if sorted(rows) != sorted(OWNERSHIP_CASES):
        only_driver = sorted(set(rows) - set(OWNERSHIP_CASES))
        only_expected = sorted(set(OWNERSHIP_CASES) - set(rows))
        _add(failures, "QW-OWN-TABLE",
             f"driver table differs from OWNERSHIP_CASES: driver-only {only_driver}, "
             f"expected-only {only_expected}")
    if sorted(pending) != sorted(OWNERSHIP_PENDING):
        _add(failures, "QW-OWN-TABLE",
             f"pending rows {sorted(pending)} != OWNERSHIP_PENDING {sorted(OWNERSHIP_PENDING)}")


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


FIXTURE_SHA = "0123456789abcdef0123456789abcdef01234567"


def _write_receipt(directory, mutate=None):
    """Write a passing 25/25 behavioral receipt; mutate(dict, lines) may edit it."""
    directory.mkdir(parents=True, exist_ok=True)
    names = [cell for cell, _driver, _env in MATRIX_CELLS]
    matrix = {
        "mode": "behavioral",
        "sha": FIXTURE_SHA,
        "requested_revision": FIXTURE_SHA,
        "runner": {"os": "Linux 6.8.0 x86_64", "nproc": 4, "image_id": "sha256:" + "ab" * 32},
        "cells": [{"name": n, "driver": d, "env": e, "result": "pass", "rc": 0,
                   "duration_s": 1} for n, d, e in MATRIX_CELLS],
        "failures": [],
    }
    raw = [f"{n} pass" for n in names]
    classification = {"mode": "behavioral", "reason": "fixture"}
    if mutate:
        mutate(matrix, raw, classification)
    (directory / "matrix.json").write_text(json.dumps(matrix, indent=2))
    (directory / "cell-results.txt").write_text("".join(line + "\n" for line in raw))
    if classification is not None:
        (directory / "classification.json").write_text(json.dumps(classification))


def _receipt_controls(controls, fresh_dir):
    def case(label, rule, mutate=None, expect_sha=FIXTURE_SHA, drop=None):
        directory = fresh_dir()
        _write_receipt(directory, mutate)
        if drop:
            (directory / drop).unlink()
        failures = verify_matrix(directory, expect_sha)
        if rule is None:
            if failures:
                controls.failed.append(f"{label}: expected pass, got {failures}")
            else:
                controls.passed += 1
                print(f"PASS (control): {label}")
        elif any(f.startswith(rule + ":") for f in failures):
            controls.passed += 1
            print(f"PASS (negative): {label} -> {rule}")
        else:
            controls.failed.append(f"{label}: expected {rule} failure, got {failures}")

    def absent(m, raw, c):
        m["cells"] = [x for x in m["cells"] if x["name"] != "aging"]
        raw[:] = [x for x in raw if not x.startswith("aging ")]

    def dup_raw(m, raw, c):
        raw.append(raw[0])

    def dup_cell(m, raw, c):
        m["cells"].append(dict(m["cells"][0]))

    def failcell(m, raw, c):
        m["cells"][3]["result"] = "FAIL"
        raw[3] = raw[3].replace(" pass", " FAIL")
        m["failures"] = [m["cells"][3]["name"]]

    def buildonly(m, raw, c):
        m["mode"] = "buildonly"

    def class_buildonly(m, raw, c):
        c["mode"] = "buildonly"

    def extra(m, raw, c):
        m["cells"].append({"name": "bogus-cell", "driver": "x", "env": "", "result": "pass"})
        raw.append("bogus-cell pass")

    def no_runner(m, raw, c):
        del m["runner"]

    def raw_only_fail(m, raw, c):
        raw[5] = raw[5].replace(" pass", " FAIL")

    def empty(m, raw, c):
        m["cells"] = []
        raw[:] = []

    def requested_differs(m, raw, c):
        m["requested_revision"] = "e" * 40

    def pass_rc_nonzero(m, raw, c):
        m["cells"][2]["rc"] = 3

    def no_rc(m, raw, c):
        del m["cells"][4]["rc"]

    def no_duration(m, raw, c):
        del m["cells"][4]["duration_s"]

    case("passing 25/25 behavioral receipt", None)
    case("requested revision differs from the checked-out sha", "QW-RCPT-SHA", requested_differs)
    case("pass cell with nonzero rc", "QW-RCPT-RESULT", pass_rc_nonzero)
    case("cell missing rc", "QW-RCPT-SHAPE", no_rc)
    case("cell missing duration_s", "QW-RCPT-SHAPE", no_duration)
    case("absent cell", "QW-RCPT-CELLS", absent)
    case("duplicated raw result line", "QW-RCPT-DUPLICATE", dup_raw)
    case("duplicated matrix cell", "QW-RCPT-DUPLICATE", dup_cell)
    case("FAIL cell", "QW-RCPT-RESULT", failcell)
    case("sha differs from expected", "QW-RCPT-SHA", expect_sha="f" * 40)
    case("matrix mode buildonly", "QW-RCPT-MODE", buildonly)
    case("classification mode buildonly", "QW-RCPT-MODE", class_buildonly)
    case("unknown extra cell", "QW-RCPT-CELLS", extra)
    case("missing classification.json", "QW-RCPT-MISSING", drop="classification.json")
    case("missing cell-results.txt", "QW-RCPT-MISSING", drop="cell-results.txt")
    case("missing runner record", "QW-RCPT-SHAPE", no_runner)
    case("raw line FAIL while matrix says pass", "QW-RCPT-RESULT", raw_only_fail)
    case("empty cells", "QW-RCPT-CELLS", empty)


def _write_ownership(directory, mutate=None):
    """Write a passing ownership receipt tree (every case x N1/N2/N4)."""
    directory.mkdir(parents=True, exist_ok=True)
    receipts, index = {}, []
    for case, minimum, ctr in OWNERSHIP_CASES:
        for n in OWNERSHIP_RTS:
            receipts[f"{case}.N{n}.json"] = {
                "case": case, "suite": "model", "min_count": minimum, "rts_n": n,
                "using_n": n, "sha": FIXTURE_SHA, "nproc": 4, "rc": 0,
                "listed": minimum, "passed": minimum, "duration_s": 1,
                "status": "pass", "reason": "", "counters_required": ctr,
                "counters": ([f"OWNERSHIP-COUNTERS case={case} test=t bufs=0"] if ctr else [])}
            index.append([case, str(n), str(minimum), str(minimum), "0", "pass", "1"])
    if mutate:
        mutate(receipts, index)
    for name, body in receipts.items():
        (directory / name).write_text(body if isinstance(body, str) else json.dumps(body))
    if index is not None:
        (directory / "index.tsv").write_text(
            "case\trts\tlisted\tpassed\trc\tstatus\tduration_s\n"
            + "".join("\t".join(r) + "\n" for r in index))


def _ownership_controls(controls, fresh_dir):
    def case(label, rule, mutate=None, expect_sha=FIXTURE_SHA, drop=None):
        directory = fresh_dir()
        _write_ownership(directory, mutate)
        if drop:
            (directory / drop).unlink()
        failures = verify_ownership(directory, expect_sha)
        if rule is None:
            if failures:
                controls.failed.append(f"{label}: expected pass, got {failures}")
            else:
                controls.passed += 1
                print(f"PASS (control): {label}")
        elif any(f.startswith(rule + ":") for f in failures):
            controls.passed += 1
            print(f"PASS (negative): {label} -> {rule}")
        else:
            controls.failed.append(f"{label}: expected {rule} failure, got {failures}")

    victim = "m4-store-contract"
    gated = next(c for c, _m, g in OWNERSHIP_CASES if g)
    plain = next(c for c, _m, g in OWNERSHIP_CASES if not g)

    def drop_row(r, idx):
        for n in OWNERSHIP_RTS:
            del r[f"{victim}.N{n}.json"]
        idx[:] = [x for x in idx if x[0] != victim]

    def rename_row(r, idx):
        for n in OWNERSHIP_RTS:
            body = r.pop(f"{victim}.N{n}.json")
            body["case"] = "m4-store-contract-v2"
            r[f"m4-store-contract-v2.N{n}.json"] = body
        for x in idx:
            if x[0] == victim:
                x[0] = "m4-store-contract-v2"

    def rename_files_only(r, idx):
        r[f"{victim}-v2.N1.json"] = r.pop(f"{victim}.N1.json")

    def wrong_sha(r, idx):
        r[f"{plain}.N2.json"]["sha"] = "e" * 40

    def wrong_rts(r, idx):
        r[f"{plain}.N2.json"]["using_n"] = 1

    def wrong_rts_n(r, idx):
        r[f"{plain}.N2.json"]["rts_n"] = 4

    def n3(r, idx):
        r["m4-store-contract.N3.json"] = dict(r[f"{victim}.N1.json"], rts_n=3, using_n=3)

    def failed(r, idx):
        r[f"{plain}.N1.json"]["status"] = "fail"

    def rc(r, idx):
        r[f"{plain}.N1.json"]["rc"] = 1

    def below_min(r, idx):
        r[f"{plain}.N1.json"]["listed"] = 1
        r[f"{plain}.N1.json"]["passed"] = 1

    def passed_ne_listed(r, idx):
        r[f"{plain}.N1.json"]["passed"] -= 1

    def pending_ran(r, idx):
        r["wp07-pending.N1.json"] = dict(r[f"{plain}.N1.json"], case="wp07-pending")

    def no_counters(r, idx):
        r[f"{gated}.N1.json"]["counters"] = []

    def counters_off(r, idx):
        r[f"{gated}.N1.json"]["counters_required"] = False

    def other_counter(r, idx):
        r[f"{gated}.N1.json"]["counters"] = ["OWNERSHIP-COUNTERS case=other test=t bufs=0"]

    def nonzero_counter(r, idx):
        r[f"{gated}.N1.json"]["counters"] = [f"OWNERSHIP-COUNTERS case={gated} test=t bufs=2"]

    def bad_json(r, idx):
        r[f"{plain}.N1.json"] = "{not json"

    def index_dup(r, idx):
        idx.append(list(idx[0]))

    def index_short(r, idx):
        del idx[0]

    def index_fail(r, idx):
        idx[0][5] = "fail"

    case("passing full ownership receipt tree", None)
    case("dropped row (all three receipts of a case)", "QW-OWN-MISSING", drop_row)
    case("renamed row (case id changed in the table)", "QW-OWN-MISSING", rename_row)
    case("renamed row also reports the unknown id", "QW-OWN-UNKNOWN", rename_row)
    case("renamed receipt files only", "QW-OWN-MISSING", rename_files_only)
    case("missing receipt (one RTS of one case)", "QW-OWN-MISSING", drop=f"{plain}.N2.json")
    case("wrong sha in one receipt", "QW-OWN-SHA", wrong_sha)
    case("wrong sha expected by the caller", "QW-OWN-SHA", expect_sha="f" * 40)
    case("wrong RTS evidence (using_n != rts_n)", "QW-OWN-RTS", wrong_rts)
    case("wrong RTS value (receipt rts_n != filename)", "QW-OWN-RTS", wrong_rts_n)
    case("unexpected RTS value N3", "QW-OWN-UNKNOWN", n3)
    case("failed receipt", "QW-OWN-RESULT", failed)
    case("nonzero rc with pass status", "QW-OWN-RESULT", rc)
    case("listed below the per-case minimum", "QW-OWN-COUNT", below_min)
    case("passed != listed", "QW-OWN-COUNT", passed_ne_listed)
    case("pending row executed and counted", "QW-OWN-UNKNOWN", pending_ran)
    case("gated case without counter lines", "QW-OWN-COUNTERS", no_counters)
    case("gated case with counters_required false", "QW-OWN-COUNTERS", counters_off)
    case("counter line of another case", "QW-OWN-COUNTERS", other_counter)
    case("nonzero counter value", "QW-OWN-COUNTERS", nonzero_counter)
    case("malformed receipt json", "QW-OWN-SHAPE", bad_json)
    case("duplicate index row", "QW-OWN-INDEX", index_dup)
    case("index row missing", "QW-OWN-INDEX", index_short)
    case("index row failed", "QW-OWN-INDEX", index_fail)
    case("missing index.tsv", "QW-OWN-MISSING", drop="index.tsv")
    case("empty receipt directory", "QW-OWN-MISSING",
         lambda r, idx: (r.clear(), idx.clear()))
    directory = fresh_dir()
    failures = verify_ownership(directory / "absent", FIXTURE_SHA)
    if any(f.startswith("QW-OWN-MISSING:") for f in failures):
        controls.passed += 1
        print("PASS (negative): ownership directory absent -> QW-OWN-MISSING")
    else:
        controls.failed.append(f"absent ownership dir: got {failures}")


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

        receipt_dirs = []

        def fresh_dir():
            tmp = Path(tempfile.mkdtemp(prefix="haskoki-qw-rcpt-"))
            receipt_dirs.append(tmp)
            allocated.append(tmp)
            return tmp / "receipt"

        _receipt_controls(controls, fresh_dir)
        _ownership_controls(controls, fresh_dir)

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
        # One must-fail control per matrix cell: dropping the cell
        # row must fail, and so must dropping a tuned leg's
        # selector while the cell name survives (a selector-less
        # leg would silently run the default).
        for cell, _driver, _env in MATRIX_CELLS:
            root = fresh()
            _drop_lines(root / QUALIFICATION_YML, cell)
            controls.expect_fail(f"drop matrix cell {cell}", root, "QW-LANE-MATRIX")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "HASKOKI_MT_PIN_ROTATE=1", "HASKOKI_MT_PIN_ROTATE=0")
        controls.expect_fail("drop the pin-rotate selector", root, "QW-LANE-MATRIX")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "HASKOKI_SIM_WAVES=", "HASKOKI_SIM_WAVES_UNSET=")
        controls.expect_fail("drop the thread-reuse selector", root, "QW-LANE-MATRIX")
        root = fresh()
        # Two pinned cells share this selector; both rows must lose
        # it before the rule can fire (added pinned cells extend
        # this count alongside MATRIX_CELLS). The static bogus
        # control sets the same variable to a non-CPU value, so the
        # needle pins the exact CPU and never touches that line.
        _rewrite(root / QUALIFICATION_YML, "HASKOKI_SOCKET_CPU=0", "HASKOKI_SOCKET_CPU=9",
                 count=2)
        controls.expect_fail("drop the pinning selector", root, "QW-LANE-MATRIX")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "HASKOKI_MT_N=8", "HASKOKI_MT_N=1")
        controls.expect_fail("retune a worker count", root, "QW-LANE-MATRIX")
        # Execution omission is not a matrix: removing the driver
        # invocation while the row table survives must fail, and so
        # must dropping the selector transport from the invocation.
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "scripts/$driver")
        controls.expect_fail("omit the driver execution", root, "QW-LANE-EXECUTE")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "docker run --rm $ENV_ARGS", "docker run --rm")
        controls.expect_fail("drop the selector transport", root, "QW-LANE-EXECUTE")
        # Mixed upload roots nest unpredictably: a bare checkout
        # file beside the runner-temp tree must fail.
        root = fresh()
        anchor = "            ${{ runner.temp }}/qualify-evidence-run.log"
        _rewrite(root / QUALIFICATION_YML, anchor,
                 anchor + "\n            classification.json")
        controls.expect_fail("mix upload roots", root, "QW-LANE-LAYOUT")
        # Native label, job set, fallback, and static-guard controls.
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "  qualify:\n    needs: [static-gates, toolchain, proxy-pair]\n    runs-on: ubuntu-latest",
                 "  qualify:\n    needs: [static-gates, toolchain, proxy-pair]\n    runs-on: [self-hosted, linux, x64]")
        controls.expect_fail("move qualify back to the self-hosted label", root, "QW-LANE-RUNNER")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "  qualify:\n    needs: [static-gates, toolchain, proxy-pair]\n    runs-on: ubuntu-latest",
                 "  qualify:\n    needs: [static-gates, toolchain, proxy-pair]\n    runs-on: ubuntu-24.04-arm")
        controls.expect_fail("mutate the qualify runner label", root, "QW-LANE-RUNNER")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "          exit 1  # buildonly-incomplete", "          exit 0  # buildonly-incomplete")
        controls.expect_fail("build-only run exits zero", root, "QW-LANE-FALLBACK")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "incomplete: behavioral prerequisites unmet (")
        controls.expect_fail("drop the build-only incomplete failure", root, "QW-LANE-FALLBACK")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "        if: always()\n        env:\n          REQUESTED_REVISION: ${{ inputs.revision || github.sha }}\n        run: |\n          # Last qualify",
                 "        if: always()\n        continue-on-error: true\n        env:\n          REQUESTED_REVISION: ${{ inputs.revision || github.sha }}\n        run: |\n          # Last qualify")
        controls.expect_fail("continue-on-error on the qualify verify step", root, "QW-LANE-VERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, '--expect-sha "$REQUESTED_REVISION"',
                 '--expect-sha "$(git rev-parse HEAD)"')
        controls.expect_fail("bind expected sha to the checkout HEAD", root, "QW-LANE-VERIFY")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "revision must be a full SHA")
        controls.expect_fail("drop the full-SHA revision gate", root, "QW-LANE-STATIC")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, "group: qualification-${{ github.event_name }}-",
                 "group: qualification-")
        controls.expect_fail("concurrency group ignores the event name", root, "QW-LANE-CONCURRENCY")
        # Checker hardening: job-level continue-on-error, the SHA
        # gate anchor, and the schedule-only cancellation expression.
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "  qualify:\n    needs: [static-gates, toolchain, proxy-pair]\n    runs-on: ubuntu-latest",
                 "  qualify:\n    needs: [static-gates, toolchain, proxy-pair]\n    continue-on-error: true\n    runs-on: ubuntu-latest")
        controls.expect_fail("job-level continue-on-error on qualify", root, "QW-LANE-VERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "  report:\n    needs: qualify\n",
                 "  report:\n    needs: qualify\n    continue-on-error: true\n")
        controls.expect_fail("job-level continue-on-error on report", root, "QW-LANE-VERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "      - name: Require an exact full-SHA revision\n",
                 "      - name: Interposed step\n        run: echo before the gate\n"
                 "      - name: Require an exact full-SHA revision\n")
        controls.expect_fail("move the SHA gate off the first step", root, "QW-LANE-STATIC")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 'HEAD $(git rev-parse HEAD)"; exit 2; }', 'HEAD $(git rev-parse HEAD)"; }')
        controls.expect_fail("remove the SHA gate exit", root, "QW-LANE-STATIC")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "cancel-in-progress: ${{ github.event_name == 'schedule' }}",
                 "cancel-in-progress: true")
        controls.expect_fail("cancel dispatch runs in progress", root, "QW-LANE-CONCURRENCY")
        # Every job: job-level continue-on-error (not only qualify/report).
        for jname, jhead in (("static-gates", "  static-gates:\n"),
                             ("toolchain", "  toolchain:\n"),
                             ("proxy-pair", "  proxy-pair:\n")):
            root = fresh()
            _rewrite(root / QUALIFICATION_YML, jhead, jhead + "    continue-on-error: true\n")
            controls.expect_fail(f"job-level continue-on-error on {jname}", root, "QW-LANE-VERIFY")
        # Ownership receipts must be inside the uploaded evidence root.
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 'OWN_DIR="$RUNNER_TEMP/qualify-evidence/ownership"',
                 'OWN_DIR="$RUNNER_TEMP/ownership"')
        controls.expect_fail("ownership receipts outside the evidence root", root, "QW-LANE-OWNERSHIP")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "            ${{ runner.temp }}/qualify-evidence/\n            ${{ runner.temp }}/qualify-evidence-run.log",
                 "            ${{ runner.temp }}/qualify-evidence-run.log")
        controls.expect_fail("evidence upload drops the evidence root", root, "QW-LANE-OWNERSHIP")
        # Ownership matrix: qualification role + workflow wiring.
        root = fresh()
        _rewrite(root / INVENTORY,
                 '{"name": "test-ownership-matrix.sh", "role": "qualification", "parent": null}',
                 '{"name": "test-ownership-matrix.sh", "role": "container", "parent": null}')
        controls.expect_fail("ownership driver joins the manifest as container", root, "QW-INV-ROLE")
        root = fresh()
        _rewrite(root / INVENTORY,
                 '{"name": "test-ownership-matrix.sh", "role": "qualification", "parent": null}',
                 '{"name": "test-ownership-matrix.sh", "role": "bogus", "parent": null}')
        controls.expect_fail("ownership driver gets an unknown role", root, "QW-INV-ROLE")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "scripts/test-ownership-matrix.sh")
        controls.expect_fail("qualify never invokes the ownership driver", root, "QW-LANE-OWNERSHIP")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 "        if: always() && steps.select.outputs.mode == 'behavioral'\n        run: |\n          set -euo pipefail\n          export HASKOKI_IMAGE=haskoki-dev:ghc-9.10.3\n          OWN_DIR",
                 "        if: steps.select.outputs.mode == 'behavioral'\n        run: |\n          set -euo pipefail\n          export HASKOKI_IMAGE=haskoki-dev:ghc-9.10.3\n          OWN_DIR")
        controls.expect_fail("ownership step skipped after a matrix failure", root, "QW-LANE-OWNERSHIP")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 'tee "$RUNNER_TEMP/qualify-evidence/ownership.log"',
                 'tee "$RUNNER_TEMP/qualify-evidence/ownership.log" || true')
        controls.expect_fail("swallow an ownership failure", root, "QW-LANE-OWNERSHIP")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "--env HASKOKI_OWN_SHA=")
        controls.expect_fail("ownership driver loses the exact SHA", root, "QW-LANE-OWNERSHIP")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "toolchain image id mismatch")
        controls.expect_fail("drop the toolchain image id verification", root, "QW-LANE-GATE")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "  report:")
        controls.expect_fail("drop the report job", root, "QW-LANE-JOBS")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "classification.json")
        controls.expect_fail("drop runtime classification", root, "QW-LANE-FALLBACK")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "behavioral")
        controls.expect_fail("drop the behavioral mode", root, "QW-LANE-FALLBACK")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "release-evidence.sh")
        controls.expect_fail("drop the build-only fallback", root, "QW-LANE-FALLBACK")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML,
                 'check-qualification-wiring.py --verify-matrix \\\n            "$RUNNER_TEMP/qualify-evidence"',
                 'check-qualification-wiring.py --self-test \\\n            "$RUNNER_TEMP/qualify-evidence"')
        controls.expect_fail("drop the qualify receipt verifier", root, "QW-LANE-VERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, '--expect-sha "$REQUESTED_REVISION"\n\n  #',
                 '--expect-sha "$REQUESTED_REVISION" || true\n\n  #')
        controls.expect_fail("swallow a verifier failure", root, "QW-LANE-VERIFY")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "duration_s")
        controls.expect_fail("drop per-cell duration from the receipt", root, "QW-LANE-VERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, '--verify-ownership \\\n            "$RUNNER_TEMP/qualify-evidence/ownership"',
                 '--self-test \\\n            "$RUNNER_TEMP/qualify-evidence/ownership"')
        controls.expect_fail("drop the qualify ownership verifier", root, "QW-LANE-OWNVERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, '--verify-ownership \\\n            evidence-in/qualify-evidence/ownership',
                 '--self-test \\\n            evidence-in/qualify-evidence/ownership')
        controls.expect_fail("drop the report ownership verifier", root, "QW-LANE-OWNVERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, '--verify-ownership \\\n            "$RUNNER_TEMP/qualify-evidence/ownership" --expect-sha "$REQUESTED_REVISION"',
                 '--verify-ownership \\\n            "$RUNNER_TEMP/qualify-evidence/ownership" --expect-sha "$REQUESTED_REVISION" || true')
        controls.expect_fail("swallow the qualify ownership verifier", root, "QW-LANE-OWNVERIFY")
        root = fresh()
        _rewrite(root / QUALIFICATION_YML, '--verify-ownership \\\n            evidence-in/qualify-evidence/ownership --expect-sha "$REQUESTED_REVISION"',
                 '--verify-ownership \\\n            evidence-in/qualify-evidence/ownership --expect-sha "$(git rev-parse HEAD)"')
        controls.expect_fail("report ownership verifier uses the checkout sha", root, "QW-LANE-OWNVERIFY")
        # Static drift between the driver's case table and the expected set.
        driver = "scripts/" + OWNERSHIP_DRIVER
        root = fresh()
        _rewrite(root / driver, "m4-store-contract|storage", "m4-store-renamed|storage")
        controls.expect_fail("driver table renames a case", root, "QW-OWN-TABLE")
        root = fresh()
        _drop_lines(root / driver, "m4-multi-session|")
        controls.expect_fail("driver table drops a case", root, "QW-OWN-TABLE")
        root = fresh()
        _rewrite(root / driver, "$2 == \"store contract\"|123|", "$2 == \"store contract\"|1|")
        controls.expect_fail("driver table lowers a minimum", root, "QW-OWN-TABLE")
        root = fresh()
        _rewrite(root / driver, "|5|active|claim-rival-refusal", "|5|active|no")
        controls.expect_fail("driver table turns counters off for a gated case", root, "QW-OWN-TABLE")
        root = fresh()
        _drop_lines(root / QUALIFICATION_YML, "HASKOKI_QUAL_ONLY=bogus")
        controls.expect_fail("drop the bogus-hint control", root, "QW-LANE-STATIC")
        # One must-fail control per matrix leg: the scenario
        # filter, the width passthrough, the socket modes, and
        # every probe-side selector.
        root = fresh()
        _drop_lines(root / "scripts/test-consumers.sh", "HASKOKI_QUAL_ONLY")
        controls.expect_fail("drop the scenario filter", root, "QW-MTX-FILTER")
        root = fresh()
        _drop_lines(root / "scripts/test-c-mutexes.sh", "HASKOKI_WIDTH_LEG")
        controls.expect_fail("drop the canary width selector", root, "QW-MTX-WIDTH")
        root = fresh()
        _drop_lines(root / "scripts/test-sim-threaded.sh", "HASKOKI_SOCKET_CPU")
        controls.expect_fail("drop the sim pinning mode", root, "QW-MTX-PIN")
        for probe, var in MATRIX_PROBES:
            root = fresh()
            _drop_lines(root / probe, var)
            controls.expect_fail(f"drop probe selector {var}", root, "QW-MTX-PROBE")
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
    if len(argv) == 5 and argv[1] == "--verify-matrix" and argv[3] == "--expect-sha":
        failures = verify_matrix(argv[2], argv[4])
        if failures:
            print(f"FAIL: matrix receipt ({len(failures)} findings):")
            for failure in failures:
                print(f"  {failure}")
            return 1
        print(f"PASS: matrix receipt ({len(MATRIX_CELLS)}/{len(MATRIX_CELLS)} behavioral, sha {argv[4]})")
        return 0
    if len(argv) == 5 and argv[1] == "--verify-ownership" and argv[3] == "--expect-sha":
        failures = verify_ownership(argv[2], argv[4])
        if failures:
            print(f"FAIL: ownership receipts ({len(failures)} findings):")
            for failure in failures:
                print(f"  {failure}")
            return 1
        total = len(OWNERSHIP_CASES) * len(OWNERSHIP_RTS)
        print(f"PASS: ownership receipts ({total}/{total}: {len(OWNERSHIP_CASES)} cases x "
              f"RTS {'/'.join(map(str, OWNERSHIP_RTS))}, sha {argv[4]})")
        return 0
    if len(argv) != 1:
        print("usage: check-qualification-wiring.py [--self-test | --verify-matrix DIR --expect-sha SHA"
              " | --verify-ownership DIR --expect-sha SHA]")
        return 2
    failures = run_all(ROOT)
    if failures:
        print(f"FAIL: qualification wiring ({len(failures)} findings):")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("PASS: qualification wiring (inventory, owners, behavioral matrix lane)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
