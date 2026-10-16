#!/usr/bin/env python3
"""Recomputing aggregate check for installed-client journey runs.

`check` reads a run directory (record files, saved logs, substituted
configs, summary) plus the required-leg table, and recomputes every
verdict from the saved evidence. A record's own status claim never
turns a failing leg into a pass; claiming pass where the recomputation
fails is reported as JR-SELF-REPORT next to the specific rule.

Run-directory layout (written by the journey driver)::

    <run>/summary.json
    <run>/records/<leg>.json
    <run>/logs/<leg>.log
    <run>/cfg/<store>.toml

Log, config and unchanged paths stored in records resolve against the
run root. The leg table is authoritative for every expectation (exit
codes, markers, refusals, verifiers, unchanged paths, order); the
summary supplies the measured module hashes at run start and end.

Failure lines look like `JR-<RULE>: <leg>: <detail>`, sorted by leg
then rule, followed by `JOURNEYS: PASS n/n` or `JOURNEYS: FAIL k/n`
where n counts the profile's required legs and k counts failure lines.
Run-level findings use the leg label `(run)`.

Stdlib only; callers run this file with `python3 -I`.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

JR_MISSING = "JR-MISSING"
JR_DUPLICATE = "JR-DUPLICATE"
JR_UNKNOWN = "JR-UNKNOWN"
JR_STATUS = "JR-STATUS"
JR_EXIT = "JR-EXIT"
JR_MARKER = "JR-MARKER"
JR_REFUSAL_UNREACHED = "JR-REFUSAL-UNREACHED"
JR_VERIFY = "JR-VERIFY"
JR_UNCHANGED = "JR-UNCHANGED"
JR_MODULE = "JR-MODULE"
JR_CONFIG = "JR-CONFIG"
JR_PIN = "JR-PIN"
JR_SETUP = "JR-SETUP"
JR_ORDER = "JR-ORDER"
JR_SELF_REPORT = "JR-SELF-REPORT"

RUN_LEG = "(run)"

# Per-leg evidence rules: a record that claims "pass" while one of
# these fails for its leg additionally draws JR-SELF-REPORT.
# Structural findings (missing/duplicate/unknown records, run-level
# module drift, order) never draw it: there is no single pass claim
# to contradict.
SELF_REPORT_TRIGGERS = frozenset([
    JR_EXIT, JR_MARKER, JR_REFUSAL_UNREACHED, JR_VERIFY, JR_UNCHANGED,
    JR_MODULE, JR_CONFIG, JR_PIN, JR_SETUP,
])

PIN_FIELDS = ("package", "package_version", "runtime_version",
              "compile_target")


class UsageError(Exception):
    pass


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_run(run_dir, profile, legs_path):
    """Return (failures, required_names).

    failures is a list of (rule, leg, detail) with rule like
    "JR-MISSING" and leg "(run)" for run-level findings. Raises
    UsageError for caller errors (unknown profile, unreadable table).
    """
    run_dir = Path(run_dir)
    try:
        table = load_json(legs_path)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read leg table {legs_path}: {exc}")
    if not isinstance(table, dict) or profile not in table.get(
            "profiles", {}):
        raise UsageError(f"unknown profile {profile!r}")
    rows = [row for row in table.get("legs", [])
            if isinstance(row, dict)
            and profile in row.get("profiles", [])]
    required = [row["name"] for row in rows]
    by_name = {row["name"]: row for row in rows}
    clients = table.get("clients", {})
    if not isinstance(clients, dict):
        clients = {}

    failures = []

    # -- summary: measured module hashes --
    start_hash = None
    try:
        summary = load_json(run_dir / "summary.json")
    except (OSError, ValueError) as exc:
        failures.append((JR_MODULE, RUN_LEG,
                         f"summary unreadable: {exc}"))
        summary = None
    if summary is not None:
        start_hash = summary.get("module_sha256_start")
        end_hash = summary.get("module_sha256_end")
        if not start_hash:
            failures.append((JR_MODULE, RUN_LEG,
                             "summary lacks module_sha256_start"))
        elif start_hash != end_hash:
            failures.append((JR_MODULE, RUN_LEG,
                             "module changed during run"))

    # -- records, grouped by claimed name --
    records_dir = run_dir / "records"
    grouped = {}
    if records_dir.is_dir():
        for path in sorted(records_dir.glob("*.json")):
            try:
                record = load_json(path)
            except (OSError, ValueError):
                continue  # no valid record; MISSING covers the leg
            name = record.get("name") if isinstance(record, dict) else None
            if not isinstance(name, str):
                continue
            grouped.setdefault(name, []).append((path.name, record))
    for name, copies in sorted(grouped.items()):
        if len(copies) > 1:
            seen = " ".join(filename for filename, _ in copies)
            failures.append((JR_DUPLICATE, name,
                             f"{len(copies)} records: {seen}"))
    records = {name: copies[0][1] for name, copies in grouped.items()}

    required_set = set(required)
    for name in sorted(records):
        if name not in required_set:
            failures.append((JR_UNKNOWN, name,
                             "record outside the profile"))

    # A missing leg that is some present leg's verification target
    # reports through JR-VERIFY, not JR-MISSING: one root cause,
    # one line.
    verified_targets = set()
    for row in rows:
        target = row.get("requires_verification")
        if target and row["name"] in records:
            verified_targets.add(target)
    for name in required:
        if name not in records and name not in verified_targets:
            failures.append((JR_MISSING, name,
                             "no record for required leg"))

    # -- per-leg evidence --
    for name in required:
        record = records.get(name)
        if record is None:
            continue
        check_leg(name, by_name[name], record, run_dir, clients,
                  start_hash, failures)

    # -- order --
    for name in required:
        record = records.get(name)
        if record is None:
            continue
        for dep in by_name[name].get("depends_on", []) or []:
            other = records.get(dep)
            if other is None:
                continue
            started = record.get("started_utc_ns")
            ended = other.get("ended_utc_ns")
            if not isinstance(started, int) or not isinstance(ended, int):
                continue
            if started < ended:
                failures.append((JR_ORDER, name,
                                 f"started before {dep} ended"))

    # -- verification (fixpoint: verifiers may themselves require
    # verification) --
    verify_done = set()
    while True:
        failed_legs = {leg for _rule, leg, _detail in failures}
        grown = False
        for name in required:
            if name in verify_done:
                continue
            record = records.get(name)
            target = by_name[name].get("requires_verification")
            if record is None or not target:
                verify_done.add(name)
                continue
            other = records.get(target)
            if other is None:
                failures.append((JR_VERIFY, name,
                                 f"verifier {target} has no record"))
            elif other.get("status") != "pass" or target in failed_legs:
                failures.append((JR_VERIFY, name,
                                 f"verifier {target} did not pass"))
            else:
                continue
            verify_done.add(name)
            grown = True
        if not grown:
            break

    # -- setup --
    failed_legs = {leg for _rule, leg, _detail in failures}
    for name in required:
        record = records.get(name)
        if record is None:
            continue
        if record.get("failure_stage") == "setup":
            failures.append((JR_SETUP, name, "failure_stage: setup"))
        elif (record.get("classification") == "setup"
                and (record.get("status") != "pass"
                     or name in failed_legs)):
            failures.append((JR_SETUP, name, "setup leg did not pass"))

    # -- self-report --
    for name in required:
        record = records.get(name)
        if record is None or record.get("status") != "pass":
            continue
        if any(rule in SELF_REPORT_TRIGGERS
               for rule, leg, _detail in failures if leg == name):
            failures.append((JR_SELF_REPORT, name,
                             "record claims pass where evidence fails"))

    failures.sort(key=lambda item: (item[1], item[0]))
    return failures, required


def check_leg(name, row, record, run_dir, clients, start_hash, failures):
    expect = row.get("expect", {}) or {}
    status = record.get("status")
    if status not in ("pass", "fail"):
        failures.append((JR_STATUS, name, f"status {status!r}"))
    if record.get("exit_code") != expect.get("exit"):
        failures.append((JR_EXIT, name,
                         f"exit {record.get('exit_code')!r}, "
                         f"expected {expect.get('exit')!r}"))
    log_rel = record.get("log")
    log_text = None
    if isinstance(log_rel, str):
        try:
            log_text = (run_dir / log_rel).read_text(encoding="utf-8",
                                                     errors="replace")
        except OSError:
            log_text = None
    if log_text is None:
        failures.append((JR_MARKER, name, "log unreadable"))
    else:
        for marker in expect.get("markers", []) or []:
            if marker not in log_text:
                failures.append((JR_MARKER, name,
                                 f"marker missing: {marker[:80]}"))
        for marker in expect.get("absent_markers", []) or []:
            if marker in log_text:
                failures.append((JR_MARKER, name,
                                 f"absent marker present: {marker[:80]}"))
        refusal = row.get("expect_refusal")
        if refusal:
            rv = refusal.get("rv")
            if rv and rv not in log_text:
                failures.append((JR_REFUSAL_UNREACHED, name,
                                 f"refusal {rv} not observed"))
            for marker in refusal.get("markers", []) or []:
                if marker not in log_text:
                    failures.append((JR_REFUSAL_UNREACHED, name,
                                     "refusal marker missing: "
                                     f"{marker[:80]}"))
    if row.get("unchanged"):
        seen = record.get("unchanged")
        before = seen.get("sha256_before") if isinstance(seen, dict) else None
        after = seen.get("sha256_after") if isinstance(seen, dict) else None
        path = seen.get("path") if isinstance(seen, dict) else None
        if path != row["unchanged"] or not before or before != after:
            failures.append((JR_UNCHANGED, name,
                             "output bytes changed during the leg"))
    if start_hash:
        module = record.get("module") or {}
        if module.get("sha256") != start_hash:
            failures.append((JR_MODULE, name,
                             "record module hash differs from run start"))
    config = record.get("config") or {}
    config_rel = config.get("file")
    config_ok = False
    if isinstance(config_rel, str):
        try:
            config_ok = (sha256_file(run_dir / config_rel)
                         == config.get("sha256"))
        except OSError:
            config_ok = False
    if not config_ok:
        failures.append((JR_CONFIG, name,
                         "saved config bytes differ from the record"))
    client = record.get("client") or {}
    pin = clients.get(client.get("name"))
    if not isinstance(pin, dict):
        failures.append((JR_PIN, name,
                         f"no pin for client {client.get('name')!r}"))
    else:
        for field in PIN_FIELDS:
            want = pin.get(field)
            if want is not None and client.get(field) != want:
                failures.append((JR_PIN, name,
                                 f"{field} {client.get(field)!r} "
                                 f"differs from pin {want!r}"))


def cmd_check(args):
    try:
        failures, required = check_run(args.run_dir, args.profile,
                                       args.legs)
    except UsageError as exc:
        print(f"journeys: {exc}", file=sys.stderr)
        return 2
    for rule, leg, detail in failures:
        print(f"{rule}: {leg}: {detail}")
    total = len(required)
    if failures:
        print(f"JOURNEYS: FAIL {len(failures)}/{total}")
        return 1
    print(f"JOURNEYS: PASS {total}/{total}")
    return 0


# ------------------------------------------------------------------
# Self-test: a synthetic five-leg fixture run plus one mutation per
# rule. The fixture lives in temp dirs only, never in the real table.
# ------------------------------------------------------------------

SETUP_LEG = "setup-client-versions"
SUCCESS_LEG = "client-action-succeeds"
VERIFIER_LEG = "action-independently-verified"
REFUSAL_LEG = "client-action-refused"
KEPT_LEG = "client-output-kept"

FIXTURE_MODULE_SHA = hashlib.sha256(b"fixture-module-bytes").hexdigest()
FIXTURE_SOURCE_SHA = hashlib.sha256(b"fixture-source").hexdigest()
FIXTURE_TOOLCHAIN_SHA = hashlib.sha256(b"fixture-toolchain").hexdigest()
FIXTURE_BUNDLE_SHA = hashlib.sha256(b"fixture-bundle").hexdigest()
FIXTURE_KEPT_SHA = hashlib.sha256(b"fixture-kept-output").hexdigest()
FIXTURE_T0 = 1780000000000000000

FIXTURE_LEGS = {
    "clients": {
        "opensc": {
            "package": "opensc",
            "package_version": "0.27.0~rc1-1",
            "runtime_argv": ["dpkg-query", "-W", "-f=${Version}",
                             "opensc"],
            "runtime_version": "0.27.0~rc1-1",
        },
        "openssl": {
            "package": "openssl",
            "package_version": "3.5.5-1ubuntu3.7",
            "runtime_argv": ["openssl", "version"],
            "runtime_version": "OpenSSL 3.5.5",
        },
        "runner": {
            "package": None,
            "package_version": None,
            "runtime_argv": None,
            "runtime_version": None,
        },
    },
    "profiles": {
        "portfolio": {"description": "self-test fixture profile"},
    },
    "legs": [
        {
            "name": SETUP_LEG,
            "profiles": ["portfolio"],
            "phase": "module",
            "client": "runner",
            "store": "setup-store",
            "argv": ["probe-versions"],
            "env": {},
            "timeout_seconds": 60,
            "expect": {"exit": 0, "markers": ["setup complete"]},
            "depends_on": [],
        },
        {
            "name": SUCCESS_LEG,
            "profiles": ["portfolio"],
            "phase": "module",
            "client": "opensc",
            "store": "shared-store",
            "argv": ["client-action"],
            "env": {},
            "timeout_seconds": 60,
            "expect": {"exit": 0,
                       "markers": ["action done"],
                       "absent_markers": ["traceback"]},
            "requires_verification": VERIFIER_LEG,
            "depends_on": [],
        },
        {
            "name": VERIFIER_LEG,
            "profiles": ["portfolio"],
            "phase": "verifier",
            "client": "openssl",
            "store": "shared-store",
            "argv": ["verify-action"],
            "env": {},
            "timeout_seconds": 60,
            "expect": {"exit": 0,
                       "markers": ["independently verified"]},
            "depends_on": [SUCCESS_LEG],
        },
        {
            "name": REFUSAL_LEG,
            "profiles": ["portfolio"],
            "phase": "module",
            "client": "opensc",
            "store": "busy-store",
            "argv": ["client-action", "--busy"],
            "env": {},
            "timeout_seconds": 60,
            "expect": {"exit": 1, "markers": ["token busy"]},
            "expect_refusal": {"rv": "CKR_SESSION_EXISTS",
                               "markers": ["token busy"]},
            "depends_on": [],
        },
        {
            "name": KEPT_LEG,
            "profiles": ["portfolio"],
            "phase": "module",
            "client": "opensc",
            "store": "shared-store",
            "argv": ["client-action", "--keep"],
            "env": {},
            "timeout_seconds": 60,
            "expect": {"exit": 0, "markers": ["output kept"]},
            "unchanged": "files/output.bin",
            "depends_on": [SUCCESS_LEG],
        },
    ],
}

# name -> (classification, client, phase, exit, log, verifies, unchanged)
FIXTURE_RECORDS = [
    (SETUP_LEG, "setup", "runner", "module", 0,
     "setup complete\n", None, False),
    (SUCCESS_LEG, "independent-client", "opensc", "module", 0,
     "action done\n", None, False),
    (VERIFIER_LEG, "independent-verifier", "openssl", "verifier", 0,
     "independently verified\n", SUCCESS_LEG, False),
    (REFUSAL_LEG, "independent-client", "opensc", "module", 1,
     "token busy: CKR_SESSION_EXISTS\n", None, False),
    (KEPT_LEG, "independent-client", "opensc", "module", 0,
     "output kept\n", None, True),
]

FIXTURE_CLIENTS = {
    "opensc": {"name": "opensc", "package": "opensc",
               "package_version": "0.27.0~rc1-1",
               "runtime_version": "0.27.0~rc1-1",
               "compile_target": None},
    "openssl": {"name": "openssl", "package": "openssl",
                "package_version": "3.5.5-1ubuntu3.7",
                "runtime_version": "OpenSSL 3.5.5",
                "compile_target": None},
    "runner": {"name": "runner", "package": None,
               "package_version": None, "runtime_version": None,
               "compile_target": None},
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def build_clean_run(root):
    """Write a fully passing fixture run under root. Returns the legs file."""
    root = Path(root)
    (root / "records").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "cfg").mkdir()
    legs_path = root / "legs.json"
    write_json(legs_path, FIXTURE_LEGS)
    names = []
    for index, spec in enumerate(FIXTURE_RECORDS):
        (name, classification, client, phase, exit_code, log_text,
         verifies, kept) = spec
        names.append(name)
        (root / "logs" / f"{name}.log").write_text(log_text,
                                                   encoding="utf-8")
        config_bytes = (f"# substituted config for {name}\n"
                        f"module = '/opt/fixture/lib/libhaskoki.so'\n"
                        ).encode("utf-8")
        config_rel = f"cfg/{name}.toml"
        (root / config_rel).write_bytes(config_bytes)
        row = next(item for item in FIXTURE_LEGS["legs"]
                   if item["name"] == name)
        record = {
            "name": name,
            "command": list(row["argv"]),
            "timeout_seconds": row["timeout_seconds"],
            "classification": classification,
            "env_overrides": {"HASKOKI_CONFIG": config_rel},
            "log": f"logs/{name}.log",
            "exit_code": exit_code,
            "status": "pass",
            "elapsed_seconds": 0.5,
            "journey": "self-test-fixture",
            "client": dict(FIXTURE_CLIENTS[client]),
            "module": {"path": "/opt/fixture/lib/libhaskoki.so",
                       "sha256": FIXTURE_MODULE_SHA},
            "config": {"file": config_rel,
                       "sha256": hashlib.sha256(config_bytes).hexdigest()},
            "expect": {"status": "pass", "exit": row["expect"]["exit"],
                       "markers": list(row["expect"]["markers"])},
            "source": {"sha": FIXTURE_SOURCE_SHA, "dirty": False},
            "artifact": {"kind": "bundle",
                         "haskoki_version": "0.5.0.0",
                         "bundle_sha256": FIXTURE_BUNDLE_SHA,
                         "image_id": None,
                         "toolchain_record_sha256": FIXTURE_TOOLCHAIN_SHA},
            "phase": phase,
            "failure_stage": None,
            "verifies": verifies,
            "unchanged": ({"path": "files/output.bin",
                           "sha256_before": FIXTURE_KEPT_SHA,
                           "sha256_after": FIXTURE_KEPT_SHA}
                          if kept else None),
            "started_utc_ns": FIXTURE_T0 + index * 20,
            "ended_utc_ns": FIXTURE_T0 + index * 20 + 10,
        }
        if "expect_refusal" in row:
            record["expect_refusal"] = dict(row["expect_refusal"])
        write_json(root / "records" / f"{name}.json", record)
    write_json(root / "summary.json", {
        "$schema": "haskoki-journey-summary/1",
        "profile": "portfolio",
        "required": names,
        "results": {name: "pass" for name in names},
        "aggregate": "pass",
        "module_sha256_start": FIXTURE_MODULE_SHA,
        "module_sha256_end": FIXTURE_MODULE_SHA,
        "first_verified_signature": {"leg": SUCCESS_LEG,
                                     "seconds": 3.5,
                                     "t0_basis": "bundle-extract"},
        "client_setup_seconds": 12.0,
        "versions": {"opensc": "0.27.0~rc1-1",
                     "openssl": "3.5.5-1ubuntu3.7"},
    })
    return legs_path


def mutate_record(root, name, update):
    path = Path(root) / "records" / f"{name}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    update(record)
    write_json(path, record)


def mutate_summary(root, update):
    path = Path(root) / "summary.json"
    summary = json.loads(path.read_text(encoding="utf-8"))
    update(summary)
    write_json(path, summary)


def drop_record(root, name):
    (Path(root) / "records" / f"{name}.json").unlink()


def set_status_fail(record):
    record["status"] = "fail"


# -- one mutation per rule -------------------------------------------

def mut_omit_leg(root):
    drop_record(root, REFUSAL_LEG)


def mut_duplicate_record(root):
    first = Path(root) / "records" / f"{SUCCESS_LEG}.json"
    (Path(root) / "records" / f"{SUCCESS_LEG}-copy.json").write_text(
        first.read_text(encoding="utf-8"), encoding="utf-8")


def mut_unknown_record(root):
    stray = {
        "name": "stray-leg",
        "command": ["stray"],
        "timeout_seconds": 60,
        "classification": "independent-client",
        "env_overrides": {},
        "log": f"logs/{SUCCESS_LEG}.log",
        "exit_code": 0,
        "status": "pass",
        "elapsed_seconds": 0.5,
        "journey": "self-test-fixture",
        "client": dict(FIXTURE_CLIENTS["opensc"]),
        "module": {"path": "/opt/fixture/lib/libhaskoki.so",
                   "sha256": FIXTURE_MODULE_SHA},
        "config": {"file": f"cfg/{SUCCESS_LEG}.toml",
                   "sha256": sha256_file(Path(root) / "cfg"
                                         / f"{SUCCESS_LEG}.toml")},
        "expect": {"status": "pass", "exit": 0,
                   "markers": ["action done"]},
        "source": {"sha": FIXTURE_SOURCE_SHA, "dirty": False},
        "artifact": {"kind": "bundle", "haskoki_version": "0.5.0.0",
                     "bundle_sha256": FIXTURE_BUNDLE_SHA,
                     "image_id": None,
                     "toolchain_record_sha256": FIXTURE_TOOLCHAIN_SHA},
        "phase": "module",
        "failure_stage": None,
        "verifies": None,
        "unchanged": None,
        "started_utc_ns": FIXTURE_T0 + 200,
        "ended_utc_ns": FIXTURE_T0 + 210,
    }
    write_json(Path(root) / "records" / "stray-leg.json", stray)


def mut_skip_status(root):
    def update(record):
        record["status"] = "skip"
    mutate_record(root, SUCCESS_LEG, update)


def mut_bad_exit(root):
    def update(record):
        record["exit_code"] = 3
    mutate_record(root, SUCCESS_LEG, update)


def mut_marker_missing(root):
    (Path(root) / "logs" / f"{SUCCESS_LEG}.log").write_text(
        "nothing useful here\n", encoding="utf-8")
    mutate_record(root, SUCCESS_LEG, set_status_fail)


def mut_refusal_unreached(root):
    (Path(root) / "logs" / f"{REFUSAL_LEG}.log").write_text(
        "token busy: CKR_GENERAL_ERROR\n", encoding="utf-8")
    mutate_record(root, REFUSAL_LEG, set_status_fail)


def mut_verifier_absent(root):
    drop_record(root, VERIFIER_LEG)
    mutate_record(root, SUCCESS_LEG, set_status_fail)


def mut_verifier_failing(root):
    mutate_record(root, VERIFIER_LEG, set_status_fail)
    mutate_record(root, SUCCESS_LEG, set_status_fail)


def mut_unchanged_output(root):
    def update(record):
        record["unchanged"]["sha256_after"] = hashlib.sha256(
            b"something-else").hexdigest()
        record["status"] = "fail"
    mutate_record(root, KEPT_LEG, update)


def mut_module_hash(root):
    def update(record):
        record["module"]["sha256"] = hashlib.sha256(
            b"other-module").hexdigest()
        record["status"] = "fail"
    mutate_record(root, KEPT_LEG, update)


def mut_module_drift(root):
    def update(summary):
        summary["module_sha256_end"] = hashlib.sha256(
            b"other-module").hexdigest()
    mutate_summary(root, update)


def mut_config_bytes(root):
    def update(record):
        record["config"]["sha256"] = hashlib.sha256(
            b"other-config").hexdigest()
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_pin_drift(root):
    def update(record):
        record["client"]["runtime_version"] = "p11tool 9.9.9"
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_setup_failed(root):
    mutate_record(root, SETUP_LEG, set_status_fail)


def mut_order_swapped(root):
    def update(record):
        record["started_utc_ns"] = FIXTURE_T0 + 20
    mutate_record(root, KEPT_LEG, update)


SELF_TEST_CASES = [
    ("clean run", set(), None,
     (0, "JOURNEYS: PASS 5/5", None)),
    ("omitted required leg", {JR_MISSING}, mut_omit_leg,
     (1, "JOURNEYS: FAIL 1/5",
      f"{JR_MISSING}: {REFUSAL_LEG}: ")),
    ("duplicated record", {JR_DUPLICATE}, mut_duplicate_record, None),
    ("record outside the profile", {JR_UNKNOWN}, mut_unknown_record,
     None),
    ("skip status", {JR_STATUS}, mut_skip_status, None),
    ("bad exit with pass status", {JR_EXIT, JR_SELF_REPORT},
     mut_bad_exit, None),
    ("marker missing from log", {JR_MARKER}, mut_marker_missing, None),
    ("refusal rv absent", {JR_REFUSAL_UNREACHED},
     mut_refusal_unreached, None),
    ("verifier leg absent", {JR_VERIFY}, mut_verifier_absent, None),
    ("verifier leg failing", {JR_VERIFY}, mut_verifier_failing, None),
    ("unchanged output changed", {JR_UNCHANGED}, mut_unchanged_output,
     None),
    ("record module hash differs", {JR_MODULE}, mut_module_hash, None),
    ("module changed during run", {JR_MODULE}, mut_module_drift, None),
    ("config bytes differ from record", {JR_CONFIG}, mut_config_bytes,
     None),
    ("client runtime differs from pin", {JR_PIN}, mut_pin_drift, None),
    ("setup leg failed", {JR_SETUP}, mut_setup_failed, None),
    ("dependent leg ran first", {JR_ORDER}, mut_order_swapped, None),
]


def check_cli_shape(tmp, legs_path, want):
    """Run the real CLI over the fixture; return an error string or None."""
    want_rc, want_last, want_line = want
    proc = subprocess.run(
        [sys.executable, "-I", str(Path(__file__).resolve()),
         "check", tmp, "--profile", "portfolio",
         "--legs", str(legs_path)],
        capture_output=True, text=True, timeout=120)
    lines = proc.stdout.splitlines()
    if proc.returncode != want_rc:
        return (f"cli exit {proc.returncode}, want {want_rc}: "
                f"{proc.stderr.strip()[:200]}")
    if not lines or lines[-1] != want_last:
        return f"cli last line {lines[-1:]}, want {want_last!r}"
    if want_line is not None and not any(line.startswith(want_line)
                                         for line in lines):
        return f"cli lacks line starting {want_line!r}"
    return None


def self_test():
    passed = 0
    total = len(SELF_TEST_CASES)
    for label, expected, mutate, cli in SELF_TEST_CASES:
        with tempfile.TemporaryDirectory(prefix="journeys-selftest-") as tmp:
            legs_path = build_clean_run(tmp)
            if mutate is not None:
                mutate(tmp)
            failures, _required = check_run(tmp, "portfolio",
                                            str(legs_path))
            observed = {rule for rule, _leg, _detail in failures}
            problem = None
            if observed != expected:
                problem = (f"expected {sorted(expected)}, "
                           f"observed {sorted(observed)}")
            elif cli is not None:
                problem = check_cli_shape(tmp, legs_path, cli)
            if problem is None:
                passed += 1
                print(f"  ok: {label}")
            else:
                print(f"  FAIL: {label}: {problem}")
    if passed == total:
        print(f"SELF-TEST: PASS {passed}/{total}")
        return 0
    print(f"SELF-TEST: FAIL {passed}/{total}")
    return 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="journeys.py",
        description="Recomputing aggregate check for journey runs.")
    parser.add_argument("--self-test", action="store_true",
                        help="run the fixture mutation suite")
    sub = parser.add_subparsers(dest="command")
    check = sub.add_parser("check", help="check a run directory")
    check.add_argument("run_dir")
    check.add_argument("--profile", required=True)
    check.add_argument("--legs",
                       default=str(Path(__file__).with_name("legs.json")))
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    if args.command == "check":
        return cmd_check(args)
    build_parser().print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
