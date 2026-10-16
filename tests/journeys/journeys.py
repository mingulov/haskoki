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
codes, markers, file assertions, refusals, verifiers, unchanged
paths, order); the summary supplies the measured module hashes at
run start and end plus the completed phases. Table order is run
order. A malformed table row or profile reports as JR-TABLE, and a
run whose profile phases are incomplete reports as JR-PHASE; both
are structural findings without JR-SELF-REPORT. The table shape is
defined by legs-schema.json and validated structurally by
--self-test.

Failure lines look like `JR-<RULE>: <leg>: <detail>`, sorted by leg
then rule, followed by `JOURNEYS: PASS n/n` or `JOURNEYS: FAIL k/n`
where n counts the profile's required legs and k counts failure lines.
Run-level findings use the leg label `(run)`.

Stdlib only; callers run this file with `python3 -I`.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePath

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
JR_TABLE = "JR-TABLE"
JR_FILE = "JR-FILE"
JR_PHASE = "JR-PHASE"
JR_SELF_REPORT = "JR-SELF-REPORT"

RUN_LEG = "(run)"

# Per-leg evidence rules: a record that claims "pass" while one of
# these fails for its leg additionally draws JR-SELF-REPORT.
# Structural findings (missing/duplicate/unknown records, table shape,
# run-level module drift, incomplete phases, order) never draw it:
# there is no single pass claim to contradict.
SELF_REPORT_TRIGGERS = frozenset([
    JR_EXIT, JR_MARKER, JR_REFUSAL_UNREACHED, JR_VERIFY, JR_UNCHANGED,
    JR_MODULE, JR_CONFIG, JR_PIN, JR_SETUP, JR_FILE,
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


KNOWN_PLACEHOLDERS = frozenset(
    ["@MODULE@", "@RUN@", "@CFG@", "@NATIVE@", "@SRC@"])
PLACEHOLDER_RE = re.compile(r"@[^@\s]+@")

PHASES = ("module", "verifier")

FILE_OPS = ("equal", "nonempty", "absent")


def unknown_placeholders(text):
    """Unknown @...@ tokens in text, sorted; known ones are allowed."""
    found = set()
    for match in PLACEHOLDER_RE.finditer(text):
        token = match.group(0)
        if token not in KNOWN_PLACEHOLDERS:
            found.add(token)
    return sorted(found)


def is_run_relative(rel):
    if not isinstance(rel, str) or not rel:
        return False
    parsed = PurePath(rel)
    return not parsed.is_absolute() and ".." not in parsed.parts


def token_contains(haystack, needle):
    """True when needle occurs in haystack as a whole token.

    A whole token is bounded on each side by the string edge,
    whitespace or a double quote.
    """
    if not needle:
        return False
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return False
        left = haystack[index - 1] if index else ""
        end = index + len(needle)
        right = haystack[end:end + 1]
        if (not left or left.isspace() or left == '"') and (
                not right or right.isspace() or right == '"'):
            return True
        start = index + 1


def validate_legs_table(table):
    """Structural problems in a leg table as (leg, detail) pairs.

    The leg label is the row name, "(row N)" for a nameless row, or
    "(run)" for top-level problems. An empty list means the table is
    structurally sound. Mirrors tests/journeys/legs-schema.json; the
    cross-references (row profiles, verification and order targets,
    the placeholder whitelist, run-relative paths) live only here.
    """
    if not isinstance(table, dict):
        return [(RUN_LEG, "leg table is not an object")]
    problems = []
    schema_id = table.get("$schema")
    if schema_id is not None and schema_id != "haskoki-journey-legs/1":
        problems.append((RUN_LEG,
                         f"leg table $schema {schema_id!r} is unexpected"))
    clients = table.get("clients")
    if not isinstance(clients, dict):
        problems.append((RUN_LEG, "leg table clients is not an object"))
        clients = {}
    else:
        for name in sorted(clients):
            problems.extend(_validate_client_pin(name, clients[name]))
    profiles = table.get("profiles")
    if not isinstance(profiles, dict):
        problems.append((RUN_LEG, "leg table profiles is not an object"))
        profiles = {}
    else:
        for name in sorted(profiles):
            problems.extend(
                _validate_profile(name, profiles[name], clients))
    legs = table.get("legs")
    if not isinstance(legs, list):
        problems.append((RUN_LEG, "leg table legs is not a list"))
        return problems
    names = set()
    for row in legs:
        name = row.get("name") if isinstance(row, dict) else None
        if isinstance(name, str) and name:
            names.add(name)
    seen = set()
    for index, row in enumerate(legs):
        label = "(row %d)" % index
        if isinstance(row, dict) and isinstance(row.get("name"), str) \
                and row.get("name"):
            label = row["name"]
        if not isinstance(row, dict):
            problems.append((label, "leg row is not an object"))
            continue
        name = row.get("name")
        if not isinstance(name, str) or not name:
            problems.append((label, "leg row lacks a name"))
        elif name in seen:
            problems.append((label, "duplicate leg name"))
        else:
            seen.add(name)
        problems.extend(
            _validate_row(row, label, profiles, clients, names))
    return problems


def _validate_client_pin(name, pin):
    if not isinstance(pin, dict):
        return [(RUN_LEG, f"client {name}: pin is not an object")]
    problems = []
    for field in ("package", "package_version", "runtime_version"):
        value = pin.get(field)
        if value is not None and (not isinstance(value, str)
                                  or not value):
            problems.append((RUN_LEG,
                             f"client {name}: {field} is not a "
                             "non-empty string"))
    argv = pin.get("runtime_argv")
    if argv is not None and (not isinstance(argv, list) or not argv
                             or not all(isinstance(a, str) for a in argv)):
        problems.append((RUN_LEG,
                         f"client {name}: runtime_argv is not a "
                         "non-empty string list"))
    target = pin.get("compile_target")
    if target is not None and (not isinstance(target, str)
                               or not target):
        problems.append((RUN_LEG,
                         f"client {name}: compile_target is not a "
                         "non-empty string"))
    return problems


def _validate_profile(name, profile, clients):
    if not isinstance(profile, dict):
        return [(RUN_LEG, f"profile {name}: not an object")]
    problems = []
    members = profile.get("clients")
    if not isinstance(members, list) or not all(isinstance(c, str)
                                                for c in members):
        problems.append((RUN_LEG,
                         f"profile {name}: clients is not a string list"))
    else:
        for member in members:
            if member not in clients:
                problems.append((RUN_LEG,
                                 f"profile {name}: unknown client {member}"))
    phases = profile.get("phases")
    if (not isinstance(phases, list) or not phases
            or not all(isinstance(p, str) for p in phases)):
        problems.append((RUN_LEG,
                         f"profile {name}: phases is not a non-empty "
                         "string list"))
    else:
        for phase in phases:
            if phase not in PHASES:
                problems.append((RUN_LEG,
                                 f"profile {name}: unknown phase {phase}"))
    return problems


def _validate_row(row, label, profiles, clients, names):
    problems = []
    members = row.get("profiles")
    if (not isinstance(members, list) or not members
            or not all(isinstance(p, str) for p in members)):
        problems.append((label, "leg profiles is not a non-empty "
                                "string list"))
    else:
        for member in members:
            if member not in profiles:
                problems.append((label, f"unknown profile {member}"))
    if row.get("phase") not in PHASES:
        problems.append((label,
                         f"phase {row.get('phase')!r} is not "
                         "module|verifier"))
    client = row.get("client")
    if not isinstance(client, str) or not client:
        problems.append((label, "leg client is not a string"))
    elif client not in clients:
        problems.append((label, f"unknown client {client}"))
    argv = row.get("argv")
    if (not isinstance(argv, list) or not argv
            or not all(isinstance(a, str) for a in argv)):
        problems.append((label, "leg argv is not a non-empty string list"))
    else:
        for token in unknown_placeholders("\n".join(argv)):
            problems.append((label,
                             f"unknown placeholder {token} in argv"))
    cwd = row.get("cwd")
    if cwd is not None:
        if not isinstance(cwd, str):
            problems.append((label, "leg cwd is not a string"))
        else:
            for token in unknown_placeholders(cwd):
                problems.append((label,
                                 f"unknown placeholder {token} in cwd"))
    env = row.get("env")
    if env is not None:
        if not isinstance(env, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in env.items()):
            problems.append((label, "leg env is not a string map"))
        else:
            joined = "\n".join([*env.keys(), *env.values()])
            for token in unknown_placeholders(joined):
                problems.append((label,
                                 f"unknown placeholder {token} in env"))
    timeout = row.get("timeout_seconds")
    if timeout is not None and (type(timeout) is not int or timeout < 1):
        problems.append((label,
                         "timeout_seconds is not a positive integer"))
    problems.extend(_validate_expect(row.get("expect"), label))
    refusal = row.get("expect_refusal")
    if refusal is not None:
        if not isinstance(refusal, dict):
            problems.append((label, "expect_refusal is not an object"))
        else:
            rv = refusal.get("rv")
            if rv is not None and not isinstance(rv, str):
                problems.append((label,
                                 "expect_refusal.rv is not a string"))
            markers = refusal.get("markers")
            if markers is not None and (
                    not isinstance(markers, list)
                    or not all(isinstance(m, str) for m in markers)):
                problems.append((label,
                                 "expect_refusal.markers is not a "
                                 "string list"))
    target = row.get("requires_verification")
    if target is not None:
        if not isinstance(target, str) or not target:
            problems.append((label, "requires_verification is not a "
                                    "non-empty string"))
        elif target not in names:
            problems.append((label,
                             "requires_verification names unknown leg "
                             f"{target}"))
    if row.get("verification") is not None:
        if row.get("verification") != "in-leg":
            problems.append((label,
                             "verification %r is not in-leg"
                             % (row.get("verification"),)))
        marker = row.get("verification_marker")
        if not isinstance(marker, str) or not marker:
            problems.append((label, "in-leg verification lacks a marker"))
    unchanged = row.get("unchanged")
    if unchanged is not None:
        if not is_run_relative(unchanged):
            problems.append((label,
                             "unchanged path is not a run-relative path"))
    deps = row.get("depends_on")
    if deps is not None:
        if not isinstance(deps, list) or not all(isinstance(d, str)
                                                 for d in deps):
            problems.append((label, "depends_on is not a string list"))
        else:
            for dep in deps:
                if dep not in names:
                    problems.append((label,
                                     f"depends_on names unknown leg {dep}"))
    store = row.get("store")
    if store is not None and (not isinstance(store, str) or not store):
        problems.append((label, "leg store is not a non-empty string"))
    return problems


def _validate_expect(expect, label):
    if not isinstance(expect, dict):
        return [(label, "leg expect is not an object")]
    problems = []
    if type(expect.get("exit")) is not int:
        problems.append((label, "expect.exit is not an integer"))
    for key in ("markers", "absent_markers"):
        value = expect.get(key)
        if value is not None and (
                not isinstance(value, list)
                or not all(isinstance(m, str) for m in value)):
            problems.append((label, f"expect.{key} is not a string list"))
    files = expect.get("files")
    if files is not None:
        if not isinstance(files, list):
            problems.append((label, "expect.files is not a list"))
        else:
            for entry in files:
                problems.extend(_validate_file_entry(entry, label))
    return problems


def _validate_file_entry(entry, label):
    if not isinstance(entry, dict):
        return [(label, "expect.files entry is not an object")]
    problems = []
    if not is_run_relative(entry.get("path")):
        problems.append((label, "expect.files entry lacks a run-relative "
                                "path"))
    op = entry.get("op")
    if op not in FILE_OPS:
        problems.append((label, f"expect.files op {op!r} is unknown"))
    if op == "equal" and not is_run_relative(entry.get("other")):
        problems.append((label, "expect.files equal lacks a run-relative "
                                "other path"))
    return problems


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
    profiles_map = table.get("profiles", {}) if isinstance(table, dict) \
        else {}
    if not isinstance(table, dict) or not isinstance(profiles_map, dict) \
            or profile not in profiles_map:
        raise UsageError(f"unknown profile {profile!r}")
    rows = [row for row in table.get("legs", [])
            if isinstance(row, dict)
            and isinstance(row.get("name"), str)
            and isinstance(row.get("profiles"), list)
            and profile in row.get("profiles")]
    required = [row["name"] for row in rows]
    by_name = {row["name"]: row for row in rows}
    clients = table.get("clients", {})
    if not isinstance(clients, dict):
        clients = {}

    failures = []

    # -- leg table shape: every problem is JR-TABLE, on the row or
    # the run --
    for leg, detail in validate_legs_table(table):
        failures.append((JR_TABLE, leg, detail))

    # -- summary: measured module hashes --
    start_hash = None
    try:
        summary = load_json(run_dir / "summary.json")
    except (OSError, ValueError) as exc:
        failures.append((JR_MODULE, RUN_LEG,
                         f"summary unreadable: {exc}"))
        summary = None
    if summary is not None and not isinstance(summary, dict):
        failures.append((JR_MODULE, RUN_LEG,
                         "summary is not an object"))
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

    # -- summary: every profile phase must be complete --
    entry = profiles_map.get(profile)
    phases = entry.get("phases") if isinstance(entry, dict) else None
    if (isinstance(phases, list) and phases
            and all(isinstance(p, str) for p in phases)
            and summary is not None):
        complete = summary.get("phases_complete")
        if not isinstance(complete, list):
            complete = []
        missing = [phase for phase in phases if phase not in complete]
        if missing:
            failures.append((JR_PHASE, RUN_LEG,
                             "phases incomplete: " + ", ".join(missing)))

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
        deps = by_name[name].get("depends_on", []) or []
        if not isinstance(deps, list):
            continue  # malformed; the validator reports JR-TABLE
        for dep in deps:
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


def check_refusal(name, refusal, log_text, failures):
    """Every given refusal item must appear in the log.

    The expectation needs a non-empty rv or non-empty markers, and
    empty output never counts as a refusal. Anything short of that is
    JR-REFUSAL-UNREACHED.
    """
    wanted = []
    rv = refusal.get("rv")
    if isinstance(rv, str) and rv:
        wanted.append(rv)
    markers = refusal.get("markers")
    if isinstance(markers, list):
        wanted.extend(marker for marker in markers
                      if isinstance(marker, str) and marker)
    if not wanted:
        failures.append((JR_REFUSAL_UNREACHED, name,
                         "refusal expects neither rv nor markers"))
    elif not log_text.strip():
        failures.append((JR_REFUSAL_UNREACHED, name,
                         "empty output never counts as a refusal"))
    else:
        if isinstance(rv, str) and rv and rv not in log_text:
            failures.append((JR_REFUSAL_UNREACHED, name,
                             f"refusal {rv} not observed"))
        for marker in wanted:
            if marker != rv and marker not in log_text:
                failures.append((JR_REFUSAL_UNREACHED, name,
                                 "refusal marker missing: "
                                 f"{marker[:80]}"))


def check_files(name, files, run_dir, failures):
    """File assertions over run-relative paths (JR-FILE).

    Malformed entries are table problems; the validator reports them
    as JR-TABLE and they are skipped here.
    """
    for entry in files:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("path")
        op = entry.get("op")
        if op not in FILE_OPS or not is_run_relative(rel):
            continue
        if op == "equal":
            other = entry.get("other")
            if not is_run_relative(other):
                continue
            try:
                same = ((run_dir / rel).read_bytes()
                        == (run_dir / other).read_bytes())
            except OSError:
                failures.append((JR_FILE, name,
                                 f"file unreadable for equal: {rel}"))
                continue
            if not same:
                failures.append((JR_FILE, name,
                                 f"file differs: {rel} != {other}"))
        elif op == "nonempty":
            try:
                data = (run_dir / rel).read_bytes()
            except OSError:
                failures.append((JR_FILE, name,
                                 f"file missing: {rel}"))
                continue
            if not data:
                failures.append((JR_FILE, name,
                                 f"file empty: {rel}"))
        else:  # absent
            target = run_dir / rel
            if target.exists() or target.is_symlink():
                failures.append((JR_FILE, name,
                                 f"file present, expected absent: {rel}"))


def check_leg(name, row, record, run_dir, clients, start_hash, failures):
    expect = row.get("expect", {})
    if not isinstance(expect, dict):
        # Malformed expectation: the validator reports JR-TABLE;
        # judge against an empty one so the leg still fails loudly.
        expect = {}
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
        if "expect_refusal" in row \
                and isinstance(row.get("expect_refusal"), dict):
            check_refusal(name, row["expect_refusal"], log_text, failures)
        if row.get("verification") == "in-leg":
            marker = row.get("verification_marker")
            if isinstance(marker, str) and marker:
                if marker not in log_text:
                    failures.append((JR_VERIFY, name,
                                     "in-leg verification marker missing: "
                                     f"{marker[:80]}"))
            # A missing marker is a table problem; the validator
            # reports it as JR-TABLE.
    check_files(name, expect.get("files", []) or [], run_dir, failures)
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
            if want is None or not isinstance(want, str):
                # Null pins mean nothing to check; a malformed pin
                # is a table problem the validator reports.
                continue
            got = client.get(field)
            if field == "runtime_version":
                if not isinstance(got, str) \
                        or not token_contains(got, want):
                    failures.append((JR_PIN, name,
                                     f"runtime_version {got!r} lacks "
                                     f"pinned token {want!r}"))
            elif got != want:
                failures.append((JR_PIN, name,
                                 f"{field} {got!r} "
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
    "$schema": "haskoki-journey-legs/1",
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
        "portfolio": {
            "description": "self-test fixture profile",
            "clients": ["opensc", "openssl", "runner"],
            "phases": ["module", "verifier"],
        },
    },
    "legs": [
        {
            "name": SETUP_LEG,
            "profiles": ["portfolio"],
            "phase": "module",
            "client": "runner",
            "store": "setup-store",
            "argv": ["probe-versions", "@MODULE@", "@NATIVE@"],
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
            "argv": ["client-action", "@RUN@/action.out"],
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
            "argv": ["verify-action", "@CFG@"],
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
            "env": {"HASKOKI_SRC": "@SRC@"},
            "timeout_seconds": 60,
            "expect": {"exit": 1, "markers": []},
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
            "cwd": "@RUN@/kept",
            "env": {},
            "timeout_seconds": 60,
            "expect": {"exit": 0,
                       "markers": ["output kept"],
                       "files": [
                           {"path": "files/equal-a.bin",
                            "op": "equal",
                            "other": "files/equal-b.bin"},
                           {"path": "files/nonempty.bin",
                            "op": "nonempty"},
                           {"path": "files/never-created.bin",
                            "op": "absent"},
                       ]},
            "verification": "in-leg",
            "verification_marker": "verified in-leg",
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
     "output kept\nverified in-leg\n", None, True),
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
    (root / "files").mkdir()
    paired = b"fixture-paired-output"
    (root / "files" / "equal-a.bin").write_bytes(paired)
    (root / "files" / "equal-b.bin").write_bytes(paired)
    (root / "files" / "nonempty.bin").write_bytes(b"fixture-bytes")
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
        "phases_complete": ["module", "verifier"],
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


def mutate_legs(root, update):
    path = Path(root) / "legs.json"
    table = json.loads(path.read_text(encoding="utf-8"))
    update(table)
    write_json(path, table)


def legs_row(table, name):
    return next(item for item in table["legs"]
                if item["name"] == name)


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


def mut_files_equal(root):
    (Path(root) / "files" / "equal-b.bin").write_bytes(b"other-bytes")
    mutate_record(root, KEPT_LEG, set_status_fail)


def mut_files_nonempty(root):
    (Path(root) / "files" / "nonempty.bin").write_bytes(b"")
    mutate_record(root, KEPT_LEG, set_status_fail)


def mut_files_absent(root):
    (Path(root) / "files" / "never-created.bin").write_bytes(b"oops")
    mutate_record(root, KEPT_LEG, set_status_fail)


def mut_placeholder_argv(root):
    def update(table):
        legs_row(table, SUCCESS_LEG)["argv"].append("@BOGUS@")
    mutate_legs(root, update)


def mut_placeholder_cwd(root):
    def update(table):
        legs_row(table, KEPT_LEG)["cwd"] = "@BOGUS@/work"
    mutate_legs(root, update)


def mut_placeholder_env(root):
    def update(table):
        legs_row(table, REFUSAL_LEG)["env"]["HASKOKI_EXTRA"] = "@BOGUS@"
    mutate_legs(root, update)


def mut_files_bad_op(root):
    def update(table):
        legs_row(table, KEPT_LEG)["expect"]["files"][0]["op"] = "bogus"
    mutate_legs(root, update)


def mut_verification_no_marker(root):
    def update(table):
        del legs_row(table, KEPT_LEG)["verification_marker"]
    mutate_legs(root, update)


def mut_refusal_vacuous(root):
    def update(table):
        legs_row(table, REFUSAL_LEG)["expect_refusal"] = {"rv": "",
                                                         "markers": []}
    mutate_legs(root, update)
    mutate_record(root, REFUSAL_LEG, set_status_fail)


def mut_refusal_empty_log(root):
    (Path(root) / "logs" / f"{REFUSAL_LEG}.log").write_text(
        "", encoding="utf-8")
    mutate_record(root, REFUSAL_LEG, set_status_fail)


def mut_refusal_markers_only(root):
    def update(table):
        legs_row(table, REFUSAL_LEG)["expect_refusal"] = {
            "markers": ["token busy"]}
    mutate_legs(root, update)


def mut_phase_partial(root):
    def update(summary):
        summary["phases_complete"] = ["module"]
    mutate_summary(root, update)


def mut_inleg_marker_missing(root):
    (Path(root) / "logs" / f"{KEPT_LEG}.log").write_text(
        "output kept\n", encoding="utf-8")
    mutate_record(root, KEPT_LEG, set_status_fail)


def mut_pin_runtime_substring(root):
    def update(record):
        record["client"]["runtime_version"] = "0.27.0~rc1-1+local"
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_pin_runtime_token(root):
    def update(record):
        record["client"]["runtime_version"] = "0.27.0~rc1-1 (amd64)"
    mutate_record(root, SUCCESS_LEG, update)


def mut_summary_shapeless(root):
    write_json(Path(root) / "summary.json", ["not", "an", "object"])


def mut_pin_package_nearmiss(root):
    def update(record):
        record["client"]["package_version"] = "0.27.0~rc1-1+local"
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


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
    ("paired files differ", {JR_FILE}, mut_files_equal, None),
    ("file empty where nonempty expected", {JR_FILE},
     mut_files_nonempty, None),
    ("file present where absent expected", {JR_FILE},
     mut_files_absent, None),
    ("unknown placeholder in argv", {JR_TABLE},
     mut_placeholder_argv, None),
    ("unknown placeholder in cwd", {JR_TABLE},
     mut_placeholder_cwd, None),
    ("unknown placeholder in env", {JR_TABLE},
     mut_placeholder_env, None),
    ("file assertion with unknown op", {JR_TABLE},
     mut_files_bad_op, None),
    ("in-leg verification without marker", {JR_TABLE},
     mut_verification_no_marker, None),
    ("refusal expects neither rv nor markers",
     {JR_REFUSAL_UNREACHED}, mut_refusal_vacuous, None),
    ("refusal with empty log", {JR_REFUSAL_UNREACHED},
     mut_refusal_empty_log, None),
    ("markers-only refusal satisfied", set(),
     mut_refusal_markers_only, None),
    ("profile phase incomplete", {JR_PHASE}, mut_phase_partial, None),
    ("in-leg verification marker missing", {JR_VERIFY},
     mut_inleg_marker_missing, None),
    ("client runtime pin only as substring", {JR_PIN},
     mut_pin_runtime_substring, None),
    ("client runtime pin as whole token", set(),
     mut_pin_runtime_token, None),
    ("client package version near-miss", {JR_PIN},
     mut_pin_package_nearmiss, None),
    ("summary is not an object", {JR_MODULE},
     mut_summary_shapeless, None),
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


def structural_checks():
    """Yield (label, problems) for the leg-table shape positives."""
    yield ("fixture leg table validates",
           validate_legs_table(FIXTURE_LEGS))
    here = Path(__file__).resolve().parent
    try:
        schema = load_json(here / "legs-schema.json")
    except (OSError, ValueError) as exc:
        yield ("committed leg table validates",
               [(RUN_LEG, f"legs-schema.json unreadable: {exc}")])
        return
    if not isinstance(schema, dict) \
            or schema.get("$id") != "haskoki-journey-legs/1":
        yield ("committed leg table validates",
               [(RUN_LEG,
                 "legs-schema.json lacks $id haskoki-journey-legs/1")])
        return
    try:
        committed = load_json(here / "legs.json")
    except (OSError, ValueError) as exc:
        yield ("committed leg table validates",
               [(RUN_LEG, f"legs.json unreadable: {exc}")])
        return
    yield ("committed leg table validates",
           validate_legs_table(committed))


def self_test():
    passed = 0
    checks = list(structural_checks())
    total = len(SELF_TEST_CASES) + len(checks)
    for label, problems in checks:
        if not problems:
            passed += 1
            print(f"  ok: {label}")
        else:
            print(f"  FAIL: {label}: {problems[0][1]}")
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
