#!/usr/bin/env python3
"""Journey runner and recomputing aggregate check for installed runs.

`run` executes the required legs of a profile against one installed
module, writing a record, a combined log and a substituted config per
leg plus a summary. `check` reads a run directory plus the
required-leg table and recomputes every verdict from the saved
evidence. A record's own status claim never overrides the recomputed
verdict; disagreeing with it in either direction is reported as
JR-SELF-REPORT next to the specific rule.

Run-directory layout (written by `run`)::

    <run>/summary.json
    <run>/records/<leg>.json
    <run>/logs/<leg>.log
    <run>/cfg/<leg>.toml

Log, config and unchanged paths stored in records resolve against the
run root. The leg table is authoritative for every expectation (exit
codes, markers, file assertions, refusals, verifiers, unchanged
paths, order); the summary supplies the measured module hashes at
run start and end plus the completed phases. Table order is run
order. A malformed table row or profile reports as JR-TABLE, as does
a profile with no legs; a run whose profile phases are incomplete
reports as JR-PHASE; both are structural findings without
JR-SELF-REPORT. A record whose module, client or config section is
not an object, or whose log path is not the leg's own, reports as
JR-RECORD. The table shape is defined by legs-schema.json and
validated structurally by --self-test.

`spki-match` compares a certificate's embedded SPKI byte for byte
with a standalone SPKI file. `issue-cert` mints a per-run ephemeral
CA leaf over a token SPKI with the openssl CLI, then runs the same
comparison. The `probes` block of the leg table pins the Java probe
bytes the engine requires before any leg that compiles them.

Failure lines look like `JR-<RULE>: <leg>: <detail>`, sorted by leg
then rule, followed by `JOURNEYS: PASS n/n` or `JOURNEYS: FAIL k/n`
where n counts the profile's required legs and k counts failure lines.
Run-level findings use the leg label `(run)`.

Stdlib only; callers run this file with `python3 -I`.
"""

import argparse
import contextlib
import hashlib
import io
import json
import os
import posixpath
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePath, PurePosixPath

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
JR_RECORD = "JR-RECORD"
JR_SELF_REPORT = "JR-SELF-REPORT"

RUN_LEG = "(run)"

# Per-leg evidence rules: a record that claims "pass" while one of
# these fails for its leg additionally draws JR-SELF-REPORT.
# Structural findings (missing/duplicate/unknown records, table shape,
# run-level module drift, incomplete phases, order) never draw it:
# there is no single pass claim to contradict.
SELF_REPORT_TRIGGERS = frozenset([
    JR_EXIT, JR_MARKER, JR_REFUSAL_UNREACHED, JR_VERIFY, JR_UNCHANGED,
    JR_MODULE, JR_CONFIG, JR_PIN, JR_SETUP, JR_FILE, JR_RECORD,
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
    probes = table.get("probes")
    if probes is not None:
        problems.extend(_validate_probes(probes))
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


def _validate_probes(probes):
    if not isinstance(probes, dict):
        return [(RUN_LEG, "leg table probes is not an object")]
    problems = []
    for name in sorted(probes):
        entry = probes[name]
        label = f"probe {name}"
        if not isinstance(entry, dict):
            problems.append((RUN_LEG, f"{label}: not an object"))
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path \
                or not is_run_relative(path):
            problems.append((RUN_LEG,
                             f"{label}: path is not a relative path"))
        sha = entry.get("sha256")
        if not isinstance(sha, str) or len(sha) != 64 \
                or any(char not in "0123456789abcdef"
                       for char in sha):
            problems.append((RUN_LEG,
                             f"{label}: sha256 is not 64 hex"))
        for key in ("compile", "run"):
            argv = entry.get(key)
            if argv is None:
                continue
            if not isinstance(argv, list) or not argv \
                    or not all(isinstance(a, str) for a in argv):
                problems.append((RUN_LEG,
                                 f"{label}: {key} is not a non-empty "
                                 "string list"))
            else:
                for token in unknown_placeholders("\n".join(argv)):
                    problems.append((RUN_LEG,
                                     f"{label}: unknown placeholder "
                                     f"{token} in {key}"))
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

    # -- a profile that resolves to no legs cannot pass --
    if not required:
        failures.append((JR_TABLE, RUN_LEG,
                         f"profile {profile} has no legs"))

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
            if type(started) is not int:
                failures.append((JR_ORDER, name,
                                 "started_utc_ns missing or invalid; "
                                 f"cannot order after {dep}"))
            elif type(ended) is not int:
                failures.append((JR_ORDER, name,
                                 f"{dep} ended_utc_ns missing or invalid; "
                                 f"cannot order {name}"))
            elif started < ended:
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

    # -- self-report: either direction of disagreement between the
    # record's own status and the recomputed verdict fails --
    for name in required:
        record = records.get(name)
        if record is None:
            continue
        leg_rules = {rule for rule, leg, _detail in failures
                     if leg == name}
        if record.get("status") == "pass":
            if leg_rules & SELF_REPORT_TRIGGERS:
                failures.append((JR_SELF_REPORT, name,
                                 "record claims pass where evidence fails"))
        elif record.get("status") == "fail" and not leg_rules:
            failures.append((JR_SELF_REPORT, name,
                             "record claims fail where evidence passes"))

    failures.sort(key=lambda item: (item[1], item[0]))
    return failures, required


def check_refusal(name, refusal, log_text, failures):
    """Every given refusal item must appear in the log.

    The expectation needs a non-empty rv or non-empty markers, and
    empty output never counts as a refusal. Anything short of that is
    JR-REFUSAL-UNREACHED. The rv must appear as a whole token;
    markers stay plain substrings.
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
        if isinstance(rv, str) and rv \
                and not token_contains(log_text, rv):
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
    # Malformed record sections fail as JR-RECORD; their own
    # semantic check is skipped while every other section is still
    # judged, so one bad section can neither raise nor mask the rest.
    bad_sections = set()
    for key in ("module", "client", "config"):
        value = record.get(key)
        if value is not None and not isinstance(value, dict):
            failures.append((JR_RECORD, name, f"{key} is not an object"))
            bad_sections.add(key)
    status = record.get("status")
    if status not in ("pass", "fail"):
        failures.append((JR_STATUS, name, f"status {status!r}"))
    exit_code = record.get("exit_code")
    if exit_code is None and record.get("failure_stage") in (
            "setup", "timeout"):
        # No real status exists; the stage carries the verdict.
        pass
    elif type(exit_code) is not int \
            or exit_code != expect.get("exit"):
        failures.append((JR_EXIT, name,
                         f"exit {exit_code!r}, "
                         f"expected {expect.get('exit')!r}"))
    log_rel = record.get("log")
    want_log = f"logs/{safe_leg(name)}.log"
    if log_rel != want_log:
        failures.append((JR_RECORD, name,
                         f"log {log_rel!r} is not the leg's own {want_log}"))
    else:
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
                check_refusal(name, row["expect_refusal"], log_text,
                              failures)
            if row.get("verification") == "in-leg":
                marker = row.get("verification_marker")
                if isinstance(marker, str) and marker:
                    if marker not in log_text:
                        failures.append(
                            (JR_VERIFY, name,
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
    if start_hash and "module" not in bad_sections:
        module = record.get("module")
        if not isinstance(module, dict):
            module = {}
        if module.get("sha256") != start_hash:
            failures.append((JR_MODULE, name,
                             "record module hash differs from run start"))
    raw_config = record.get("config")
    config = raw_config if isinstance(raw_config, dict) else {}
    config_rel = config.get("file")
    config_ok = False
    if isinstance(config_rel, str):
        try:
            config_ok = (sha256_file(run_dir / config_rel)
                         == config.get("sha256"))
        except OSError:
            config_ok = False
    if not config_ok and "config" not in bad_sections:
        failures.append((JR_CONFIG, name,
                         "saved config bytes differ from the record"))
    raw_client = record.get("client")
    client = raw_client if isinstance(raw_client, dict) else {}
    # The pin always comes from the leg table row, never from the
    # record's own client claim; a record naming another client fails.
    row_client = row.get("client")
    pin = clients.get(row_client) if isinstance(row_client, str) else None
    if "client" in bad_sections:
        pass  # already flagged as JR-RECORD; nothing to judge
    elif not isinstance(pin, dict):
        failures.append((JR_PIN, name,
                         f"no pin for client {row_client!r}"))
    elif client.get("name") != row_client:
        failures.append((JR_PIN, name,
                         f"record client {client.get('name')!r} differs "
                         f"from leg client {row_client!r}"))
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
# Run: execute the required legs against one installed module.
#
# The driver enforces the installed-only contract and owns the output
# root, then hands off here. Every leg runs as exact argv with a
# timeout and no pipes; each leg writes its record, its combined log
# and its substituted config even when it cannot run. Placeholders in
# argv, cwd and env come from the fixed whitelist; anything else is a
# setup problem for the leg and the checker reports the table shape
# separately. Versions are probed per phase for the clients that
# phase uses. A module-only run writes a partial summary and skips the
# aggregate judgement; a verifier append reuses the stored module
# path, recomputes the time to first verified signature over the
# merged run, then judges.
# ------------------------------------------------------------------

class SetupRefusal(Exception):
    pass


EMPTY_SHA = hashlib.sha256(b"").hexdigest()
DEFAULT_TIMEOUT = 120

FAILURE_BY_RULE = {
    JR_EXIT: "exit",
    JR_MARKER: "marker",
    JR_REFUSAL_UNREACHED: "refusal-unreached",
    JR_VERIFY: "verification",
    JR_UNCHANGED: "unchanged",
    JR_FILE: "file",
    JR_PIN: "pin",
    JR_MODULE: "module",
    JR_CONFIG: "config",
}


def find_src_root():
    return Path(__file__).resolve().parent.parent.parent


def substitute_text(text, mapping):
    """Expand every placeholder in one pass over the raw text.

    A substituted value that itself holds token-shaped text stays
    literal; replacement output is never rescanned.
    """
    def _once(match):
        token = match.group(0)
        return mapping.get(token, token)
    return re.sub(r"@[A-Z_]+@", _once, text)


def substitute_config_template(text, journey_dir, module_path):
    return substitute_text(text, {"@JOURNEY_DIR@": journey_dir,
                                  "@MODULE@": module_path})


def safe_leg(leg):
    return leg.replace("/", "_")


def classify_row(row):
    explicit = row.get("classification")
    if explicit in ("independent-client", "independent-verifier",
                    "native-consumer", "setup"):
        return explicit
    client = row.get("client")
    if client == "runner":
        return "setup"
    if client == "native":
        return "native-consumer"
    if row.get("phase") == "verifier":
        return "independent-verifier"
    return "independent-client"


def find_verifies(leg, rows):
    for row in rows:
        if row.get("requires_verification") == leg:
            return row.get("name")
    return None


def hash_run_file(run_dir, rel):
    try:
        return sha256_file(run_dir / rel)
    except OSError:
        return EMPTY_SHA


def probe_client_versions(pin):
    pkg_obs = None
    rt_obs = None
    failed = False
    pkg = pin.get("package")
    if isinstance(pkg, str) and pkg:
        try:
            proc = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}", pkg],
                capture_output=True, text=True, errors="replace",
                timeout=30)
            out = (proc.stdout or "").strip()
            if proc.returncode == 0 and out:
                pkg_obs = out.splitlines()[0].strip()
                if not pkg_obs:
                    failed = True
            else:
                failed = True
        except (OSError, subprocess.SubprocessError):
            failed = True
    argv = pin.get("runtime_argv")
    if isinstance(argv, list) and argv and all(
            isinstance(a, str) for a in argv):
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                errors="replace", timeout=30)
            combined = ((proc.stdout or "") + "\n"
                        + (proc.stderr or "")).strip()
            if proc.returncode == 0 and combined:
                rt_obs = combined
            else:
                failed = True
        except (OSError, subprocess.SubprocessError):
            failed = True
    return pkg_obs, rt_obs, failed


def config_template_for(store, src_root):
    if not isinstance(store, str) or not store:
        return None
    candidate = (src_root / "tests" / "journeys" / store
                 / f"haskoki-{store}.toml")
    try:
        if candidate.is_file():
            return candidate
    except OSError:
        return None
    return None


def synthesize_config_text(leg):
    return (
        f"# Synthesized journey config for {leg}; no template "
        "matched the store.\n"
        "schema_version = 1\n"
        "profile = \"demo-maximal\"\n"
        "\n"
        "[storage]\n"
        "kind = \"memory\"\n"
        "\n"
        "[engine]\n"
        "kind = \"openssl\"\n"
        "allow_synthetic_fallback = false\n"
        "private_library_context = true\n"
        "\n"
        "[trace]\n"
        "enabled = false\n"
    )


def probe_setup_note(argv_raw, ctx):
    """Setup note when a referenced probe fails its pinned SHA.

    Returns None when no leg argv references a pinned probe, or when
    every referenced probe matches. A leg references a probe with the
    exact `@SRC@/<path>` element.
    """
    probes = ctx.get("probes")
    if not isinstance(probes, dict) or not probes:
        return None
    src_root = ctx.get("src_root")
    if src_root is None:
        return None
    src_root = Path(src_root)
    for name in sorted(probes):
        entry = probes[name]
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        want = entry.get("sha256")
        if not isinstance(path, str) or not path:
            continue
        if not isinstance(want, str) or not want:
            continue
        marker = "@SRC@/" + path
        if not any(isinstance(item, str) and item == marker
                   for item in argv_raw):
            continue
        try:
            got = sha256_file(src_root / path)
        except OSError:
            got = None
        if got != want:
            return (f"probe provenance mismatch: {name} bytes differ "
                    f"from pin {want[:16]}")
    return None


def run_one_leg(run_dir, row, profile_rows, clients, ctx):
    name = row["name"]
    tag = safe_leg(name)
    store = row.get("store") or "default"
    stores_dir = run_dir / "stores" / store
    stores_dir.mkdir(parents=True, exist_ok=True)
    cfg_rel = f"cfg/{tag}.toml"
    cfg_path = run_dir / cfg_rel
    template = config_template_for(row.get("store"), ctx["src_root"])
    if template is not None:
        try:
            text = template.read_text(encoding="utf-8")
        except OSError as exc:
            raise SetupRefusal(
                f"config template unreadable for {name}: {exc}")
        text = substitute_config_template(
            text, str(run_dir / "stores" / store),
            ctx["module_path"])
    else:
        text = synthesize_config_text(name)
    cfg_path.write_text(text, encoding="utf-8")
    cfg_sha = sha256_file(cfg_path)
    mapping = {
        "@MODULE@": ctx["module_path"],
        "@RUN@": str(run_dir),
        "@CFG@": str(cfg_path),
        "@NATIVE@": ctx["native_dir"],
        "@SRC@": str(ctx["src_root"]),
    }
    argv_raw = row.get("argv", [])
    problems = unknown_placeholders("\n".join(
        a for a in argv_raw if isinstance(a, str)))
    cwd_raw = row.get("cwd")
    if isinstance(cwd_raw, str):
        problems.extend(unknown_placeholders(cwd_raw))
    env_raw = row.get("env") or {}
    if isinstance(env_raw, dict):
        joined = "\n".join(
            [k for k in env_raw if isinstance(k, str)]
            + [v for v in env_raw.values()
               if isinstance(v, str)])
        problems.extend(unknown_placeholders(joined))
    log_rel = f"logs/{tag}.log"
    log_path = run_dir / log_rel
    record_path = run_dir / "records" / f"{tag}.json"
    started_ns = time.time_ns()
    mono_start = time.monotonic()
    exit_code = 0
    setup_note = None
    timed_out = False
    probe_note = None
    if not problems:
        probe_note = probe_setup_note(argv_raw, ctx)
    if problems:
        setup_note = ("setup: unknown placeholder "
                      + ", ".join(sorted(set(problems))))
        exit_code = None
        log_path.write_text(setup_note + "\n", encoding="utf-8")
    elif probe_note is not None:
        setup_note = probe_note
        exit_code = None
        log_path.write_text(probe_note + "\n", encoding="utf-8")
    else:
        argv = [substitute_text(a, mapping) for a in argv_raw]
        if isinstance(cwd_raw, str):
            cwd = substitute_text(cwd_raw, mapping)
        else:
            cwd = str(run_dir)
        home = run_dir / "home"
        home.mkdir(parents=True, exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "HASKOKI_CONFIG": str(cfg_path),
        }
        for key, value in env_raw.items():
            env[substitute_text(key, mapping)] = substitute_text(
                value, mapping)
        timeout = row.get("timeout_seconds")
        if type(timeout) is not int or timeout < 1:
            timeout = DEFAULT_TIMEOUT
        unchanged_rel = row.get("unchanged")
        if not is_run_relative(unchanged_rel):
            unchanged_rel = None
        before = (hash_run_file(run_dir, unchanged_rel)
                  if unchanged_rel else None)
        try:
            with open(log_path, "wb") as handle:
                proc = subprocess.Popen(
                    argv, cwd=cwd, env=env, stdout=handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True)
                try:
                    proc.wait(timeout=timeout)
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    exit_code = None
                    with open(log_path, "ab") as append:
                        append.write(
                            f"\ntimeout after {timeout}s\n".encode(
                                "utf-8", "replace"))
                finally:
                    # Reap the whole group on every path: a leg that
                    # exits while a holder child still runs must not
                    # leave it behind.
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
        except FileNotFoundError as exc:
            if exc.filename == cwd:
                setup_note = f"setup: cwd not found: {exc.filename}"
            else:
                setup_note = f"setup: binary not found: {exc.filename}"
            exit_code = None
            with open(log_path, "ab") as append:
                append.write((setup_note + "\n").encode(
                    "utf-8", "replace"))
        except OSError as exc:
            setup_note = f"setup: cannot start leg: {exc}"
            exit_code = None
            with open(log_path, "ab") as append:
                append.write((setup_note + "\n").encode(
                    "utf-8", "replace"))
        ended_ns = time.time_ns()
        mono_end = time.monotonic()
        after = (hash_run_file(run_dir, unchanged_rel)
                 if unchanged_rel else None)
        return finish_leg_record(
            run_dir, row, profile_rows, clients, ctx, name, tag,
            argv, timeout, env, log_rel, record_path, cfg_rel,
            cfg_sha, exit_code, setup_note, timed_out,
            unchanged_rel, before, after, started_ns, ended_ns,
            mono_end - mono_start)
    ended_ns = time.time_ns()
    mono_end = time.monotonic()
    return finish_leg_record(
        run_dir, row, profile_rows, clients, ctx, name, tag,
        list(argv_raw), DEFAULT_TIMEOUT, {}, log_rel,
        record_path, cfg_rel, cfg_sha, exit_code, setup_note,
        timed_out, None, None, None, started_ns, ended_ns,
        mono_end - mono_start)


def finish_leg_record(run_dir, row, profile_rows, clients, ctx,
                      name, tag, argv, timeout, env, log_rel,
                      record_path, cfg_rel, cfg_sha, exit_code,
                      setup_note, timed_out, unchanged_rel,
                      before, after, started_ns, ended_ns,
                      elapsed):
    client_name = row.get("client")
    pin = clients.get(client_name)
    if not isinstance(pin, dict):
        pin = {}
    seen = ctx["versions"].get(client_name, {})
    compile_target = pin.get("compile_target")
    if not isinstance(compile_target, str):
        compile_target = None
    record = {
        "name": name,
        "command": list(argv),
        "timeout_seconds": timeout,
        "classification": classify_row(row),
        "env_overrides": dict(env),
        "log": log_rel,
        "exit_code": exit_code,
        "status": "pass",
        "elapsed_seconds": elapsed,
        "journey": ctx["profile"],
        "client": {
            "name": client_name,
            "package": pin.get("package"),
            "package_version": seen.get("package_version"),
            "runtime_version": seen.get("runtime_version"),
            "compile_target": compile_target,
        },
        "module": {"path": ctx["module_path"],
                   "sha256": ctx["start_hash"]},
        "config": {"file": cfg_rel, "sha256": cfg_sha},
        "expect": {
            "status": "pass",
            "exit": row.get("expect", {}).get("exit"),
            "markers": list(row.get("expect", {}).get("markers")
                            or []),
        },
        "source": {"sha": ctx["source_sha"],
                   "dirty": ctx["source_dirty"]},
        "artifact": dict(ctx["artifact"]),
        "phase": row.get("phase"),
        "failure_stage": None,
        "verifies": find_verifies(name, profile_rows),
        "unchanged": ({"path": unchanged_rel,
                       "sha256_before": before,
                       "sha256_after": after}
                      if unchanged_rel else None),
        "started_utc_ns": started_ns,
        "ended_utc_ns": ended_ns,
    }
    absent = row.get("expect", {}).get("absent_markers")
    if isinstance(absent, list) and absent:
        record["expect"]["absent_markers"] = list(absent)
    if "expect_refusal" in row and isinstance(
            row.get("expect_refusal"), dict):
        record["expect_refusal"] = dict(row["expect_refusal"])
    if setup_note is not None or seen.get("setup_failed"):
        record["status"] = "fail"
        record["failure_stage"] = "setup"
        record["exit_code"] = None
    elif timed_out:
        record["status"] = "fail"
        record["failure_stage"] = "timeout"
        record["exit_code"] = None
    else:
        probe = []
        check_leg(name, row, record, run_dir, clients,
                  ctx["start_hash"], probe)
        if probe:
            record["status"] = "fail"
            record["failure_stage"] = FAILURE_BY_RULE.get(
                probe[0][0], "exit")
    write_json(record_path, record)
    return record


def compute_first_verified(required, by_name, records, run_dir,
                           t0_ns, t0_basis):
    for name in required:
        row = by_name.get(name)
        record = records.get(name)
        if row is None or record is None:
            continue
        if record.get("status") != "pass":
            continue
        target = row.get("requires_verification")
        if target:
            other = records.get(target)
            if other is not None and other.get("status") == "pass":
                ended = record.get("ended_utc_ns")
                if isinstance(ended, int) and isinstance(
                        t0_ns, int):
                    return {"leg": name,
                            "seconds": (ended - t0_ns) / 1e9,
                            "t0_basis": t0_basis}
            continue
        if row.get("verification") == "in-leg":
            marker = row.get("verification_marker")
            log_rel = record.get("log")
            if (isinstance(marker, str) and marker
                    and isinstance(log_rel, str)):
                try:
                    text = (run_dir / log_rel).read_text(
                        encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if marker in text:
                    ended = record.get("ended_utc_ns")
                    if isinstance(ended, int) and isinstance(
                            t0_ns, int):
                        return {"leg": name,
                                "seconds": (ended - t0_ns) / 1e9,
                                "t0_basis": t0_basis}
    return None


def load_table_or_refuse(legs_path):
    try:
        table = load_json(legs_path)
    except (OSError, ValueError) as exc:
        raise SetupRefusal(f"cannot read leg table: {exc}")
    if not isinstance(table, dict):
        raise SetupRefusal("leg table is not an object")
    return table


def profile_rows(table, profile):
    rows = [row for row in table.get("legs", [])
            if isinstance(row, dict)
            and isinstance(row.get("name"), str)
            and isinstance(row.get("profiles"), list)
            and profile in row.get("profiles")]
    return rows


def capture_versions(rows, clients):
    versions = {}
    for row in rows:
        client = row.get("client")
        if client in versions:
            continue
        pin = clients.get(client)
        if not isinstance(pin, dict):
            versions[client] = {"package_version": None,
                                "runtime_version": None,
                                "setup_failed": True}
            continue
        pkg_obs, rt_obs, failed = probe_client_versions(pin)
        versions[client] = {"package_version": pkg_obs,
                            "runtime_version": rt_obs,
                            "setup_failed": failed}
    return versions


def cmd_run(args):
    try:
        return run_impl(args)
    except SetupRefusal as exc:
        print(f"JOURNEY-SETUP: {exc}", file=sys.stderr)
        return 2


def run_impl(args):
    legs_path = args.legs or str(
        Path(__file__).with_name("legs.json"))
    table = load_table_or_refuse(legs_path)
    profiles_map = table.get("profiles", {})
    if not isinstance(profiles_map, dict) \
            or args.profile not in profiles_map:
        raise SetupRefusal(f"unknown profile {args.profile!r}")
    clients = table.get("clients", {})
    if not isinstance(clients, dict):
        clients = {}
    if args.out and args.out_existing:
        raise SetupRefusal("choose one output root")
    if args.out_existing:
        return run_verifier_append(args, table, clients,
                                   legs_path)
    if not args.out:
        raise SetupRefusal("output root missing")
    return run_new(args, table, clients, legs_path)


def parse_source_flags(args):
    sha = args.source_sha
    if not isinstance(sha, str) or not sha:
        raise SetupRefusal("source sha unavailable")
    dirty_flag = args.source_dirty
    if dirty_flag == "true":
        dirty = True
    elif dirty_flag == "false":
        dirty = False
    else:
        raise SetupRefusal("source dirty flag required")
    basis = args.source_dirty_basis
    if basis not in ("measured", "caller"):
        raise SetupRefusal("source dirty basis required")
    return sha, dirty, basis


def parse_client_setup(args):
    raw = args.client_setup_seconds
    if raw is None or raw == "":
        return None, "not-measured"
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise SetupRefusal("client setup seconds malformed")
    if value < 0:
        raise SetupRefusal("client setup seconds malformed")
    return value, "caller"


def _link_target_escapes(name, target, hard):
    """True when a tar link target resolves outside the prefix.

    Symlink targets resolve against the link's own directory;
    hardlink targets name a member from the archive root.
    """
    if PurePosixPath(target).is_absolute():
        return True
    if hard:
        shape = PurePosixPath(posixpath.normpath(target))
    else:
        parent = PurePosixPath(name).parent
        shape = PurePosixPath(posixpath.normpath(
            str(parent / target)))
    return shape.is_absolute() or ".." in shape.parts


def screen_bundle_members(bundle_tar):
    """Refuse unsafe bundle members before anything is extracted.

    Absolute paths, '..' components and links resolving outside the
    install prefix are refused here, never after extraction.
    """
    try:
        handle = tarfile.open(bundle_tar, "r:*")
    except (OSError, tarfile.TarError) as exc:
        raise SetupRefusal(f"bundle unreadable: {exc}")
    with handle:
        for member in handle.getmembers():
            name = member.name
            if PurePosixPath(name).is_absolute():
                raise SetupRefusal(
                    f"bundle member is absolute: {name[:80]}")
            if ".." in PurePosixPath(name).parts:
                raise SetupRefusal(
                    f"bundle member escapes the prefix: {name[:80]}")
            if member.issym():
                if _link_target_escapes(name, member.linkname, False):
                    raise SetupRefusal(
                        "bundle link escapes the prefix: "
                        f"{name[:80]}")
            elif member.islnk():
                if _link_target_escapes(name, member.linkname, True):
                    raise SetupRefusal(
                        "bundle link escapes the prefix: "
                        f"{name[:80]}")


def install_bundle(bundle_tar, run_dir):
    try:
        t0_ns = time.time_ns()
    except OSError as exc:
        raise SetupRefusal(f"clock unreadable: {exc}")
    prefix = run_dir / "prefix"
    prefix.mkdir(parents=True, exist_ok=False)
    screen_bundle_members(bundle_tar)
    try:
        proc = subprocess.run(
            ["tar", "xzf", bundle_tar, "--no-same-owner",
             "--no-same-permissions", "-C", str(prefix)],
            capture_output=True, text=True, errors="replace",
            timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupRefusal(f"bundle extraction failed: {exc}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "").strip()[:200]
                  or "tar failed")
        raise SetupRefusal(f"bundle extraction failed: {detail}")
    matches = sorted(prefix.glob("haskoki-*/lib/libhaskoki.so"))
    if len(matches) != 1:
        raise SetupRefusal("bundle layout unexpected")
    candidate = matches[0]
    if candidate.is_symlink() or not candidate.is_file():
        raise SetupRefusal("bundle module is not a regular file")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(prefix.resolve())
    except ValueError:
        raise SetupRefusal("bundle module escapes the prefix")
    module_path = str(resolved)
    try:
        bundle_sha = sha256_file(bundle_tar)
    except OSError:
        raise SetupRefusal("bundle file missing")
    leaf = matches[0].parent.parent.name
    if leaf.startswith("haskoki-") and len(leaf) > len("haskoki-"):
        version = leaf[len("haskoki-"):]
    else:
        version = "unknown"
    base = matches[0].parent.parent
    try:
        toolchain_sha = sha256_file(base / "toolchain-record.txt")
    except OSError:
        raise SetupRefusal("not an installed bundle")
    if not (base / "closure" / "review.txt").is_file():
        raise SetupRefusal("not an installed bundle")
    ctl = base / "bin" / "haskoki-ctl"
    if not ctl.is_file() or not os.access(ctl, os.X_OK):
        raise SetupRefusal("not an installed bundle")
    return module_path, bundle_sha, version, toolchain_sha, t0_ns


def module_provenance(module_path, artifact_image):
    real = os.path.realpath(module_path)
    if "dist-newstyle" in Path(real).parts:
        raise SetupRefusal("source-tree build path")
    if not os.path.isfile(real):
        raise SetupRefusal("module file missing")
    lib = os.path.dirname(real)
    base = os.path.dirname(lib)
    try:
        toolchain_sha = sha256_file(
            os.path.join(base, "toolchain-record.txt"))
    except OSError:
        raise SetupRefusal("not an installed bundle")
    if not os.path.isfile(
            os.path.join(base, "closure", "review.txt")):
        raise SetupRefusal("not an installed bundle")
    ctl = os.path.join(base, "bin", "haskoki-ctl")
    if not os.path.isfile(ctl) or not os.access(ctl, os.X_OK):
        raise SetupRefusal("not an installed bundle")
    leaf = os.path.basename(base)
    if leaf.startswith("haskoki-") and len(leaf) > len("haskoki-"):
        version = leaf[len("haskoki-"):]
    else:
        version = "unknown"
    try:
        start_hash = sha256_file(real)
    except OSError:
        raise SetupRefusal("module file missing")
    image_id = artifact_image or None
    kind = "image" if image_id else "bundle"
    artifact = {"kind": kind, "haskoki_version": version,
                "bundle_sha256": None, "image_id": image_id,
                "toolchain_record_sha256": toolchain_sha}
    return real, start_hash, artifact


def run_new(args, table, clients, legs_path):
    out = args.out
    if not os.path.isabs(out):
        raise SetupRefusal("output root not absolute")
    run_dir = Path(out)
    if run_dir.exists() or run_dir.is_symlink():
        raise SetupRefusal("output root exists")
    phase = args.phase or "all"
    if phase not in ("all", "module"):
        raise SetupRefusal("verifier phase needs an existing run")
    if args.module and args.bundle_tar:
        raise SetupRefusal("choose one module source")
    if not args.module and not args.bundle_tar:
        raise SetupRefusal("module source missing")
    if not args.native_dir or not os.path.isabs(args.native_dir):
        raise SetupRefusal("native dir not absolute")
    fixture = os.path.join(args.native_dir, "token_fixture")
    if not os.path.isfile(fixture) or not os.access(fixture, os.X_OK):
        raise SetupRefusal("native binary missing")
    sha, dirty, dirty_basis = parse_source_flags(args)
    setup_seconds, setup_basis = parse_client_setup(args)
    run_dir.mkdir(parents=True, exist_ok=False)
    for sub in ("records", "logs", "cfg", "stores", "home",
                "out"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    src_root = find_src_root()
    if args.bundle_tar:
        if not os.path.isabs(args.bundle_tar):
            raise SetupRefusal("bundle path not absolute")
        (module_path, bundle_sha, version, toolchain_sha,
         t0_ns) = install_bundle(args.bundle_tar, run_dir)
        t0_basis = "bundle-extract"
        try:
            start_hash = sha256_file(module_path)
        except OSError:
            raise SetupRefusal("module file missing")
        image_id = args.artifact_image or None
        kind = "image" if image_id else "bundle"
        artifact = {"kind": kind, "haskoki_version": version,
                    "bundle_sha256": bundle_sha,
                    "image_id": image_id,
                    "toolchain_record_sha256": toolchain_sha}
    else:
        if not os.path.isabs(args.module):
            raise SetupRefusal("module path not absolute")
        try:
            t0_ns = time.time_ns()
        except OSError as exc:
            raise SetupRefusal(f"clock unreadable: {exc}")
        t0_basis = "module-phase-start"
        (module_path, start_hash,
         artifact) = module_provenance(args.module,
                                       args.artifact_image)
    rows = profile_rows(table, args.profile)
    if phase == "module":
        selected = [row for row in rows
                    if row.get("phase") == "module"]
    else:
        selected = list(rows)
    versions = capture_versions(selected, clients)
    probes = table.get("probes")
    if not isinstance(probes, dict):
        probes = {}
    ctx = {"module_path": module_path,
           "native_dir": str(Path(args.native_dir).resolve()),
           "src_root": src_root,
           "profile": args.profile,
           "source_sha": sha,
           "source_dirty": dirty,
           "artifact": artifact,
           "start_hash": start_hash,
           "versions": versions,
           "probes": probes}
    records = {}
    for row in selected:
        record = run_one_leg(run_dir, row, rows, clients, ctx)
        records[row["name"]] = record
    try:
        end_hash = sha256_file(module_path)
    except OSError:
        end_hash = "missing"
    required = [row["name"] for row in selected]
    by_name = {row["name"]: row for row in rows}
    first = compute_first_verified(required, by_name, records,
                                   run_dir, t0_ns, t0_basis)
    entry = profiles_map_entry(table, args.profile)
    if phase == "module":
        phases_complete = ["module"]
        aggregate = "fail"
    else:
        phases_complete = list(entry.get("phases") or [])
        aggregate = ("pass" if required and all(
            record.get("status") == "pass"
            for record in records.values()) else "fail")
    summary = {
        "$schema": "haskoki-journey-summary/1",
        "profile": args.profile,
        "required": required,
        "results": {name: records[name].get("status", "fail")
                    for name in required},
        "aggregate": aggregate,
        "phases_complete": phases_complete,
        "module_sha256_start": start_hash,
        "module_sha256_end": end_hash,
        "first_verified_signature": first,
        "client_setup_seconds": setup_seconds,
        "client_setup_seconds_basis": setup_basis,
        "versions": {name: {
            "package_version": seen.get("package_version"),
            "runtime_version": seen.get("runtime_version")}
            for name, seen in versions.items()},
        "source": {"sha": sha, "dirty": dirty,
                   "dirty_basis": dirty_basis},
        "artifact": dict(artifact),
        "module_path": module_path,
        "native_dir": ctx["native_dir"],
        "src_root": str(src_root),
        "t0_ns": t0_ns,
        "t0_basis": t0_basis,
    }
    write_json(run_dir / "summary.json", summary)
    if phase == "module":
        done = sum(1 for name in required
                   if records[name].get("status") == "pass")
        print(f"JOURNEYS: PARTIAL {done}/{len(required)} "
              "(module phase complete)")
        return 0 if done == len(required) else 1
    failures, _required = check_run(str(run_dir), args.profile,
                                    legs_path)
    # The stored claim follows the recomputed verdict, so the two
    # never disagree; this only ever downgrades a pass to a fail.
    summary["aggregate"] = "fail" if failures else "pass"
    write_json(run_dir / "summary.json", summary)
    for rule, leg, detail in failures:
        print(f"{rule}: {leg}: {detail}")
    total = len(_required)
    if failures:
        print(f"JOURNEYS: FAIL {len(failures)}/{total}")
        return 1
    print(f"JOURNEYS: PASS {total}/{total}")
    return 0


def profiles_map_entry(table, profile):
    profiles_map = table.get("profiles", {})
    entry = profiles_map.get(profile)
    return entry if isinstance(entry, dict) else {}


def run_verifier_append(args, table, clients, legs_path):
    if args.module or args.bundle_tar or args.native_dir \
            or args.source_sha or args.source_dirty \
            or args.client_setup_seconds or args.artifact_image:
        raise SetupRefusal(
            "existing run reuses its module and provenance")
    phase = args.phase or "verifier"
    if phase != "verifier":
        raise SetupRefusal(
            "existing run takes the verifier phase only")
    run_dir = Path(args.out_existing)
    if not run_dir.is_dir():
        raise SetupRefusal("run directory missing")
    try:
        summary = load_json(run_dir / "summary.json")
    except (OSError, ValueError) as exc:
        raise SetupRefusal(
            f"summary unreadable: {exc}")
    if not isinstance(summary, dict):
        raise SetupRefusal("summary is not an object")
    complete = summary.get("phases_complete")
    if not isinstance(complete, list) or "module" not in complete:
        raise SetupRefusal("module phase incomplete")
    if "verifier" in complete:
        raise SetupRefusal("verifier phase already complete")
    module_path = summary.get("module_path")
    native_dir = summary.get("native_dir")
    src_root = summary.get("src_root")
    source = summary.get("source")
    artifact = summary.get("artifact")
    t0_ns = summary.get("t0_ns")
    t0_basis = summary.get("t0_basis")
    if not isinstance(module_path, str) or not module_path \
            or not isinstance(native_dir, str) or not native_dir:
        raise SetupRefusal("stored module path missing")
    if not isinstance(source, dict) \
            or not isinstance(source.get("sha"), str) \
            or not isinstance(source.get("dirty"), bool):
        raise SetupRefusal("stored source missing")
    if not isinstance(artifact, dict):
        raise SetupRefusal("stored artifact missing")
    try:
        start_hash = sha256_file(module_path)
        start_ok = True
    except OSError:
        start_ok = False
        start_hash = summary.get("module_sha256_start")
    stored_start = summary.get("module_sha256_start")
    if start_ok and isinstance(stored_start, str) \
            and stored_start and start_hash != stored_start:
        start_hash = stored_start
    elif not isinstance(stored_start, str) or not stored_start:
        raise SetupRefusal("stored module hash missing")
    else:
        start_hash = stored_start
    rows = profile_rows(table, args.profile)
    selected = [row for row in rows
                if row.get("phase") == "verifier"]
    versions = capture_versions(selected, clients)
    try:
        src_path = Path(src_root) if src_root else find_src_root()
    except (TypeError, ValueError, OSError):
        src_path = find_src_root()
    probes = table.get("probes")
    if not isinstance(probes, dict):
        probes = {}
    ctx = {"module_path": module_path,
           "native_dir": native_dir,
           "src_root": src_path,
           "profile": args.profile,
           "source_sha": source["sha"],
           "source_dirty": source["dirty"],
           "artifact": artifact,
           "start_hash": start_hash,
           "versions": versions,
           "probes": probes}
    records = {}
    records_dir = run_dir / "records"
    if records_dir.is_dir():
        for path in sorted(records_dir.glob("*.json")):
            try:
                record = load_json(path)
            except (OSError, ValueError):
                continue
            name = record.get("name") if isinstance(
                record, dict) else None
            if isinstance(name, str):
                records.setdefault(name, record)
    for row in selected:
        if row["name"] in records:
            raise SetupRefusal(
                f"verifier leg already recorded: {row['name']}")
        record = run_one_leg(run_dir, row, rows, clients, ctx)
        records[row["name"]] = record
    try:
        end_hash = sha256_file(module_path)
    except OSError:
        end_hash = "missing"
    required = [row["name"] for row in rows]
    by_name = {row["name"]: row for row in rows}
    first = compute_first_verified(required, by_name, records,
                                   run_dir, t0_ns, t0_basis)
    entry = profiles_map_entry(table, args.profile)
    phases = list(entry.get("phases") or ["module", "verifier"])
    merged_versions = dict(summary.get("versions") or {})
    for name, seen in versions.items():
        merged_versions[name] = {
            "package_version": seen.get("package_version"),
            "runtime_version": seen.get("runtime_version")}
    stored_results = summary.get("results")
    if not isinstance(stored_results, dict):
        stored_results = {}
    results = dict(stored_results)
    for row in selected:
        results[row["name"]] = records[row["name"]].get(
            "status", "fail")
    aggregate = ("pass" if all(
        results.get(name) == "pass" for name in required)
        else "fail")
    summary.update({
        "required": required,
        "results": results,
        "aggregate": aggregate,
        "phases_complete": phases,
        "module_sha256_start": start_hash,
        "module_sha256_end": end_hash,
        "first_verified_signature": first,
        "versions": merged_versions,
    })
    write_json(run_dir / "summary.json", summary)
    failures, _required = check_run(str(run_dir), args.profile,
                                    legs_path)
    # The stored claim follows the recomputed verdict, so the two
    # never disagree; this only ever downgrades a pass to a fail.
    summary["aggregate"] = "fail" if failures else "pass"
    write_json(run_dir / "summary.json", summary)
    for rule, leg, detail in failures:
        print(f"{rule}: {leg}: {detail}")
    total = len(_required)
    if failures:
        print(f"JOURNEYS: FAIL {len(failures)}/{total}")
        return 1
    print(f"JOURNEYS: PASS {total}/{total}")
    return 0


# ------------------------------------------------------------------
# Matched-certificate tooling: a stdlib DER walk to the
# subjectPublicKeyInfo inside tbsCertificate, compared byte for byte
# with a standalone SPKI file; plus a per-run ephemeral CA that
# issues a leaf over a token SPKI with the openssl CLI (argv form,
# no shell) and then runs the same comparison.
# ------------------------------------------------------------------

class DerError(Exception):
    pass


def _der_tlv(data, offset, end):
    """One TLV at offset as (tag, value_offset, value_len, next)."""
    if offset >= end:
        raise DerError("truncated tag")
    tag = data[offset]
    pos = offset + 1
    if tag & 0x1F == 0x1F:
        while True:
            if pos >= end:
                raise DerError("truncated tag")
            byte = data[pos]
            pos += 1
            if not byte & 0x80:
                break
    if pos >= end:
        raise DerError("truncated length")
    first = data[pos]
    pos += 1
    if first & 0x80 == 0:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise DerError("indefinite length")
        if pos + count > end:
            raise DerError("truncated length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > end:
        raise DerError("truncated value")
    return tag, pos, length, pos + length


def _der_children(data, offset, end):
    """Children of one constructed value as (tag, value, full) triples."""
    nodes = []
    pos = offset
    while pos < end:
        tag, val_off, val_len, nxt = _der_tlv(data, pos, end)
        nodes.append((tag, data[val_off:val_off + val_len],
                      data[pos:nxt]))
        pos = nxt
    return nodes


def _der_oid(value):
    """Dotted string for OID value bytes (without tag or length)."""
    if not value:
        raise DerError("empty OID")
    first = value[0]
    parts = [first // 40, first % 40]
    num = 0
    pending = False
    for byte in value[1:]:
        num = (num << 7) | (byte & 0x7F)
        if byte & 0x80:
            pending = True
        else:
            parts.append(num)
            num = 0
            pending = False
    if pending:
        raise DerError("truncated OID")
    return ".".join(str(part) for part in parts)


def _cert_spki(cert_bytes):
    """Full TLV bytes of the SPKI inside tbsCertificate.

    The SPKI is the 7th child (index 6) of tbsCertificate, counting
    the [0] version.
    """
    top = _der_children(cert_bytes, 0, len(cert_bytes))
    if len(top) != 1 or top[0][0] != 0x30:
        raise DerError("certificate shape")
    outer = _der_children(top[0][1], 0, len(top[0][1]))
    if not outer or outer[0][0] != 0x30:
        raise DerError("tbsCertificate shape")
    tbs = _der_children(outer[0][1], 0, len(outer[0][1]))
    if len(tbs) < 7:
        raise DerError("tbsCertificate children")
    tag, _value, full = tbs[6]
    if tag != 0x30:
        raise DerError("subjectPublicKeyInfo shape")
    return full


def _spki_alg_oid(spki_bytes):
    """Dotted algorithm OID of one DER SubjectPublicKeyInfo."""
    top = _der_children(spki_bytes, 0, len(spki_bytes))
    if len(top) != 1 or top[0][0] != 0x30:
        raise DerError("SPKI shape")
    inner = _der_children(top[0][1], 0, len(top[0][1]))
    if not inner or inner[0][0] != 0x30:
        raise DerError("SPKI algorithm")
    alg = _der_children(inner[0][1], 0, len(inner[0][1]))
    if not alg or alg[0][0] != 0x06:
        raise DerError("SPKI algorithm OID")
    return _der_oid(alg[0][1])


def report_spki(cert_bytes, key_bytes):
    """Compare and print; return the process exit code."""
    try:
        cert_spki = _cert_spki(cert_bytes)
    except DerError as exc:
        print(f"SPKI-ERROR malformed certificate: {exc}",
              file=sys.stderr)
        return 2
    if cert_spki == key_bytes:
        print("SPKI-MATCH")
        return 0
    try:
        cert_oid = _spki_alg_oid(cert_spki)
        key_oid = _spki_alg_oid(key_bytes)
    except DerError as exc:
        print(f"SPKI-ERROR malformed public key: {exc}",
              file=sys.stderr)
        return 2
    print(f"SPKI-MISMATCH cert={cert_oid} key={key_oid}")
    return 1


def cmd_spki_match(args):
    try:
        cert_bytes = Path(args.cert_der).read_bytes()
        key_bytes = Path(args.spki_der).read_bytes()
    except OSError as exc:
        print(f"SPKI-ERROR cannot read input: {exc}", file=sys.stderr)
        return 2
    return report_spki(cert_bytes, key_bytes)


def cmd_issue_cert(args):
    out_dir = Path(args.out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"issue-cert: cannot create out dir: {exc}",
              file=sys.stderr)
        return 2
    if not isinstance(args.cn, str) or not args.cn:
        print("issue-cert: cn is required", file=sys.stderr)
        return 2
    try:
        Path(args.pub).read_bytes()
    except OSError as exc:
        print(f"issue-cert: cannot read pub: {exc}", file=sys.stderr)
        return 2
    ca_key = str(out_dir / "ca.key")
    ca_pem = str(out_dir / "ca.pem")
    token_pub = str(out_dir / "token-pub.pem")
    leaf_pem = str(out_dir / "leaf.pem")
    leaf_der = str(out_dir / "leaf.der")
    steps = [
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:P-256", "-nodes", "-keyout", ca_key,
         "-out", ca_pem, "-subj", "/CN=journey-ca", "-days", "2"],
        ["openssl", "pkey", "-pubin", "-inform", "DER",
         "-in", args.pub, "-out", token_pub],
        ["openssl", "x509", "-new", "-CA", ca_pem, "-CAkey", ca_key,
         "-force_pubkey", token_pub, "-subj", "/CN=" + args.cn,
         "-days", "2", "-out", leaf_pem],
        ["openssl", "x509", "-in", leaf_pem, "-outform", "DER",
         "-out", leaf_der],
    ]
    for step in steps:
        try:
            proc = subprocess.run(step, capture_output=True, text=True,
                                  errors="replace", timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"issue-cert: cannot run {' '.join(step[:2])}: {exc}",
                  file=sys.stderr)
            return 2
        if proc.returncode != 0:
            detail = (((proc.stderr or "").strip() + "\n"
                       + (proc.stdout or "").strip()).strip()[:300]
                       or "openssl step failed")
            print(f"issue-cert: {' '.join(step[:2])} failed: {detail}",
                  file=sys.stderr)
            return 2
    try:
        cert_bytes = Path(leaf_der).read_bytes()
        key_bytes = Path(args.pub).read_bytes()
    except OSError as exc:
        print(f"issue-cert: cannot read outputs: {exc}",
              file=sys.stderr)
        return 2
    return report_spki(cert_bytes, key_bytes)


# ------------------------------------------------------------------
# Self-test: a synthetic five-leg fixture run plus one mutation per
# rule, plus live run-path checks over tiny synthetic legs, bundles
# and runs. Everything lives in temp dirs only, never in the real
# table.
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

# Pinned SPKI bytes for the spki-match self-test. The fixture pin was
# derived once with the openssl CLI (`x509 -pubkey` then `pkey
# -outform DER`) from tests/fixtures/cert-selfsigned.der, so the
# walker is judged against an independent source, never against
# itself. The EC pin is one fixed P-256 public key for the mismatch
# control. Both are frozen; the input bytes must not churn.
PINNED_FIXTURE_SPKI_HEX = (
    "30820122300d06092a864886f70d01010105000382010f003082010a0282"
    "010100bf06cfc7c613df6425b568f13697625708a0b97f49b1343d29ce09"
    "61bb67730e6fa4fe794c2afc6ca0b6380404018619d7a7f6947476a91d21"
    "1dc342912580583b2ee50853fa7b6a550cd9b5b7a54579d08c7eadfc5e7f"
    "9357731665acdc6c4ed6fe2d24c0f8b895431caf126be76206eda8207baa"
    "ee1a0735eb653ba96bd962b0554a7cb009059b98ece07d99dec5e5f7b2ac"
    "5c1ca708ac23233707c796dc94079d9c545da66dd490b9e8ced298173b5b"
    "baed83adc6c1a3dbc1a609fa4ced6e66a56ac18dccad5b049387def33adf"
    "cf7c4d854b920f1418ce82350a5330fc3cf68da2a99e5f5814c50f0ff218"
    "a96240aef3d757be14eb3e198eb855d6f79a3d0203010001"
)
FIXED_EC_SPKI_HEX = (
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004175172"
    "1e2f28eb0a73c04b96b1eb25bfc9fc7b018054f38c7d51b7939e7062599a"
    "6f358d6c95037ff34243583e86f3c0b60818d4b53a4bf8c7c15cdf963d16"
    "b5"
)
RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"

# Java probe provenance for the self-test. The bytes live at
# tests/journeys/java/JavaTokenProbe.java; the SHA-256 below is the
# value the engine requires before any leg that compiles the probe.
PROBE_PATH = "tests/journeys/java/JavaTokenProbe.java"
PROBE_SHA = (
    "c1c77e8459f1c45de3fae2dcf8279848f206a60fc8379e50480d57d7ec24"
    "3eb6"
)

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
        "versions": {
            "opensc": {"package_version": "0.27.0~rc1-1",
                       "runtime_version": "0.27.0~rc1-1"},
            "openssl": {"package_version": "3.5.5-1ubuntu3.7",
                        "runtime_version": "OpenSSL 3.5.5"},
        },
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


def mut_status_fail_clean(root):
    mutate_record(root, SUCCESS_LEG, set_status_fail)


def mut_empty_profile(root):
    def update(table):
        table["legs"] = []
    mutate_legs(root, update)
    for spec in FIXTURE_RECORDS:
        drop_record(root, spec[0])


def mut_client_pin_bypass(root):
    def update(record):
        record["client"] = dict(FIXTURE_CLIENTS["runner"])
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_order_missing_started(root):
    def update(record):
        del record["started_utc_ns"]
    mutate_record(root, KEPT_LEG, update)


def mut_order_bad_ended(root):
    # Drop the verification link so the bad stamp draws only JR-ORDER
    # instead of cascading through the verifier into JR-VERIFY.
    def update_table(table):
        del legs_row(table, SUCCESS_LEG)["requires_verification"]
    mutate_legs(root, update_table)

    def update(record):
        record["ended_utc_ns"] = "soon"
    mutate_record(root, SUCCESS_LEG, update)


def mut_refusal_rv_substring(root):
    (Path(root) / "logs" / f"{REFUSAL_LEG}.log").write_text(
        "token busy: CKR_SESSION_EXISTS_NOT\n", encoding="utf-8")
    mutate_record(root, REFUSAL_LEG, set_status_fail)


def mut_exit_bool(root):
    def update(record):
        record["exit_code"] = False
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_exit_float(root):
    def update(record):
        record["exit_code"] = 0.0
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_log_other_leg(root):
    def update(record):
        record["log"] = f"logs/{REFUSAL_LEG}.log"
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_record_client_shapeless(root):
    def update(record):
        record["client"] = "opensc"
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_exit_null_setup(root):
    def update(record):
        record["exit_code"] = None
        record["failure_stage"] = "setup"
        record["status"] = "fail"
    mutate_record(root, SETUP_LEG, update)


def mut_exit_null_normal(root):
    def update(record):
        record["exit_code"] = None
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_exit_null_timeout_markers_missing(root):
    (Path(root) / "logs" / f"{SUCCESS_LEG}.log").write_text(
        "nothing useful here\n", encoding="utf-8")

    def update(record):
        record["exit_code"] = None
        record["failure_stage"] = "timeout"
        record["status"] = "fail"
    mutate_record(root, SUCCESS_LEG, update)


def mut_exit_null_timeout_clean(root):
    def update(record):
        record["exit_code"] = None
        record["failure_stage"] = "timeout"
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
    ("verifier leg failing", {JR_VERIFY, JR_SELF_REPORT},
     mut_verifier_failing, None),
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
    ("fail status with clean evidence", {JR_SELF_REPORT},
     mut_status_fail_clean, None),
    ("profile with no legs", {JR_TABLE},
     mut_empty_profile, None),
    ("record names a different client than the leg", {JR_PIN},
     mut_client_pin_bypass, None),
    ("dependent leg without a start stamp", {JR_ORDER},
     mut_order_missing_started, None),
    ("dependency without a valid end stamp", {JR_ORDER},
     mut_order_bad_ended, None),
    ("refusal rv only as a substring", {JR_REFUSAL_UNREACHED},
     mut_refusal_rv_substring, None),
    ("boolean exit code", {JR_EXIT},
     mut_exit_bool, None),
    ("float exit code", {JR_EXIT},
     mut_exit_float, None),
    ("record points at another leg's log", {JR_RECORD},
     mut_log_other_leg, None),
    ("record client is not an object", {JR_RECORD},
     mut_record_client_shapeless, None),
    ("setup leg with a null exit", {JR_SETUP},
     mut_exit_null_setup, None),
    ("ordinary leg with a null exit", {JR_EXIT},
     mut_exit_null_normal, None),
    ("timeout leg with a null exit and missing markers", {JR_MARKER},
     mut_exit_null_timeout_markers_missing, None),
    ("timeout leg with a null exit and clean evidence",
     {JR_SELF_REPORT}, mut_exit_null_timeout_clean, None),
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


def fixture_versions_problems():
    """Problems when the fixture summary versions diverge from `run`.

    The producer writes one object per client with exactly the
    package_version and runtime_version keys; the fixture must keep
    that shape so receipts read one form.
    """
    with tempfile.TemporaryDirectory(
            prefix="journeys-versions-") as tmp:
        build_clean_run(tmp)
        summary = load_json(Path(tmp) / "summary.json")
    versions = summary.get("versions")
    if not isinstance(versions, dict) or not versions:
        return [(RUN_LEG,
                 "fixture summary versions is not a non-empty object")]
    for name in sorted(versions):
        seen = versions[name]
        if not isinstance(seen, dict):
            return [(RUN_LEG,
                     f"fixture summary versions[{name}] is not an object")]
        if set(seen) != {"package_version", "runtime_version"}:
            return [(RUN_LEG,
                     f"fixture summary versions[{name}] lacks the "
                     "producer keys")]
    return []


def structural_checks():
    """Yield (label, problems) for the leg-table shape positives."""
    yield ("fixture leg table validates",
           validate_legs_table(FIXTURE_LEGS))
    yield ("fixture summary versions match the producer shape",
           fixture_versions_problems())
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


RUN_CHECK_PROFILE = "portfolio"


def _run_check_ctx(run_dir,
                   module_path="/opt/fixture/lib/libhaskoki.so"):
    return {
        "module_path": module_path,
        "native_dir": "/opt/fixture/native",
        "src_root": find_src_root(),
        "profile": RUN_CHECK_PROFILE,
        "source_sha": "ab" * 20,
        "source_dirty": False,
        "artifact": {
            "kind": "bundle",
            "haskoki_version": "0.5.0.0",
            "bundle_sha256": FIXTURE_BUNDLE_SHA,
            "image_id": None,
            "toolchain_record_sha256": FIXTURE_TOOLCHAIN_SHA,
        },
        "start_hash": FIXTURE_MODULE_SHA,
        "versions": {
            "runner": {"package_version": None,
                       "runtime_version": None},
        },
        "probes": {},
    }


def _run_check_row(name, argv, env=None, cwd=None, timeout=10,
                   expect_exit=0):
    row = {
        "name": name,
        "profiles": [RUN_CHECK_PROFILE],
        "phase": "module",
        "client": "runner",
        "store": "synthetic-store",
        "argv": list(argv),
        "env": dict(env or {}),
        "timeout_seconds": timeout,
        "expect": {"exit": expect_exit, "markers": []},
        "depends_on": [],
    }
    if cwd is not None:
        row["cwd"] = cwd
    return row


def _run_check_leg(tmp, row, ctx=None):
    run_dir = Path(tmp) / "run"
    for sub in ("records", "logs", "cfg", "stores", "home", "out"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    if ctx is None:
        ctx = _run_check_ctx(run_dir)
    clients = {"runner": {"package": None, "package_version": None,
                          "runtime_argv": None,
                          "runtime_version": None}}
    record = run_one_leg(run_dir, row, [row], clients, ctx)
    return run_dir, record


def _empty_profile_table(desc):
    return {
        "$schema": "haskoki-journey-legs/1",
        "clients": {},
        "profiles": {RUN_CHECK_PROFILE: {
            "description": desc,
            "clients": [],
            "phases": ["module", "verifier"],
        }},
        "legs": [],
    }


def _run_check_args(tmp, legs_path, out="run", module="/abs/fake/x.so",
                    native_dir="/abs/fake/native"):
    return argparse.Namespace(
        profile=RUN_CHECK_PROFILE, out=str(Path(tmp) / out),
        out_existing=None, module=module, bundle_tar=None,
        native_dir=native_dir, phase="all", legs=str(legs_path),
        source_sha="ab" * 20, source_dirty="false",
        source_dirty_basis="caller", client_setup_seconds=None,
        artifact_image=None)


def check_substitute_once(_tmp):
    mapping = {"@MODULE@": "M-@RUN@", "@RUN@": "R"}
    if substitute_text("@MODULE@", mapping) != "M-@RUN@":
        return "a value holding another token was expanded again"
    multi = substitute_text("@A@/@B@", {"@A@": "x@B@", "@B@": "y"})
    if multi != "x@B@/y":
        return f"multi-token expansion gave {multi!r}"
    return None


def check_config_template_once(_tmp):
    got = substitute_config_template(
        "dir=@JOURNEY_DIR@ mod=@MODULE@", "J-@MODULE@", "M")
    if got != "dir=J-@MODULE@ mod=M":
        return f"the template pass expanded twice: {got!r}"
    return None


def check_native_fixture_is_file(tmp):
    native = Path(tmp) / "dir-native"
    (native / "token_fixture").mkdir(parents=True)
    table = _empty_profile_table("native shape probe")
    legs_path = Path(tmp) / "legs.json"
    write_json(legs_path, table)
    args = _run_check_args(tmp, legs_path, native_dir=str(native))
    try:
        run_new(args, table, {}, str(legs_path))
    except SetupRefusal as exc:
        if "native binary missing" in str(exc):
            return None
        return f"wrong refusal: {exc}"
    return "a directory named token_fixture passed the native guard"


HOLDER_SCRIPT = (
    "import fcntl\n"
    "import os\n"
    "import sys\n"
    "import time\n"
    "from pathlib import Path\n"
    "lock, pidfile, seconds = (sys.argv[1], sys.argv[2],\n"
    "                          float(sys.argv[3]))\n"
    "fh = open(lock, 'w')\n"
    "fcntl.flock(fh, fcntl.LOCK_EX)\n"
    "Path(pidfile).write_text(str(os.getpid()))\n"
    "time.sleep(seconds)\n"
)

SPAWNER_SCRIPT = (
    "import subprocess\n"
    "import sys\n"
    "import time\n"
    "from pathlib import Path\n"
    "holder, lock, pidfile, seconds = (sys.argv[1], sys.argv[2],\n"
    "                                  sys.argv[3], sys.argv[4])\n"
    "subprocess.Popen([sys.executable, holder, lock, pidfile, seconds])\n"
    "for _ in range(100):\n"
    "    if Path(pidfile).exists():\n"
    "        break\n"
    "    time.sleep(0.1)\n"
)


def check_holder_reaped(tmp):
    import fcntl
    tmp = Path(tmp)
    holder = tmp / "holder.py"
    spawner = tmp / "spawner.py"
    holder.write_text(HOLDER_SCRIPT, encoding="utf-8")
    spawner.write_text(SPAWNER_SCRIPT, encoding="utf-8")
    lock = tmp / "holder.lock"
    pidfile = tmp / "holder.pid"
    row = _run_check_row(
        "holder-probe",
        [sys.executable, str(spawner), str(holder), str(lock),
         str(pidfile), "60"])
    _run_dir, record = _run_check_leg(tmp, row)
    if record.get("status") != "pass":
        return ("the spawner leg did not pass: "
                f"{record.get('failure_stage')}")
    if not pidfile.exists():
        return "the holder never signalled readiness"
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except ValueError:
        return "the holder pid file is malformed"
    # Death by signal is asynchronous; poll for release. A survivor
    # holds its lock for the full minute, far beyond this window.
    held = True
    with open(lock, "w") as handle:
        for _ in range(50):
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                time.sleep(0.1)
                continue
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            except OSError:
                pass
            held = False
            break
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    if held:
        return "an orphaned holder still holds its lock"
    return None


def _write_tar_member(tar, name, data=b"ok", mode=0o644,
                      linkname=None, linktype=None):
    info = tarfile.TarInfo(name)
    if linktype is not None:
        info.type = linktype
        info.linkname = linkname or ""
        info.mode = mode
        tar.addfile(info)
        return
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def _bundle_layout(tar, leaf="haskoki-9", module_link=None):
    _write_tar_member(tar, f"{leaf}/ok.txt", data=b"benign")
    if module_link is None:
        _write_tar_member(tar, f"{leaf}/lib/libhaskoki.so",
                           data=b"fake-module-bytes")
    else:
        _write_tar_member(tar, f"{leaf}/lib/libhaskoki.so",
                           linkname=module_link,
                           linktype=tarfile.SYMTYPE)
    _write_tar_member(tar, f"{leaf}/toolchain-record.txt",
                       data=b"fake-toolchain")
    _write_tar_member(tar, f"{leaf}/closure/review.txt",
                       data=b"fake-review")
    _write_tar_member(tar, f"{leaf}/bin/haskoki-ctl",
                       data=b"#!/bin/sh\nexit 0\n", mode=0o755)


def _screen_case(workdir, build, label):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    run_dir = workdir / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    bundle = workdir / "bundle.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        build(tar)
    try:
        install_bundle(str(bundle), run_dir)
    except SetupRefusal:
        leftovers = list((run_dir / "prefix").iterdir())
        if leftovers:
            return (f"{label} was refused after extracting "
                    f"{len(leftovers)} entries")
        return None
    return f"{label} was accepted"


def check_bundle_absolute_member(tmp):
    def build(tar):
        _bundle_layout(tar)
        _write_tar_member(tar, "/abs-evil")
    return _screen_case(tmp, build,
                        "a bundle member with an absolute path")


def check_bundle_dotdot_member(tmp):
    def build(tar):
        _bundle_layout(tar)
        _write_tar_member(tar, "../evil")
    return _screen_case(tmp, build,
                        "a bundle member with a .. component")


def check_bundle_outside_links(tmp):
    tmp = Path(tmp)
    cases = [
        ("absolute symlink", "haskoki-9/lib/evil-abs", "/etc/passwd",
         tarfile.SYMTYPE),
        ("escaping symlink", "haskoki-9/lib/evil-rel",
         "../../../etc/passwd", tarfile.SYMTYPE),
        ("escaping hardlink", "haskoki-9/lib/evil-hard", "../outside",
         tarfile.LNKTYPE),
    ]
    for label, name, target, kind in cases:
        def build(tar, name=name, target=target, kind=kind):
            _bundle_layout(tar)
            _write_tar_member(tar, name, linkname=target,
                               linktype=kind)
        problem = _screen_case(tmp / label.replace(" ", "-"), build,
                               f"a bundle with an {label}")
        if problem is not None:
            return problem
    return None


def check_bundle_module_is_regular(tmp):
    def build(tar):
        _bundle_layout(tar, module_link="../real-lib")
        _write_tar_member(tar, "haskoki-9/real-lib",
                           data=b"real-module-bytes")
    workdir = Path(tmp)
    run_dir = workdir / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    bundle = workdir / "bundle.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        build(tar)
    try:
        install_bundle(str(bundle), run_dir)
    except SetupRefusal:
        return None
    return "a bundle whose module is a link was accepted"


def check_bundle_installs(tmp):
    tmp = Path(tmp)
    run_dir = tmp / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    bundle = tmp / "bundle.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        _bundle_layout(tar)
    try:
        module_path, _sha, _ver, _tool, _t0 = install_bundle(
            str(bundle), run_dir)
    except SetupRefusal as exc:
        return f"a well-formed bundle was refused: {exc}"
    if not module_path.endswith("libhaskoki.so"):
        return f"unexpected module path {module_path!r}"
    if not Path(module_path).is_file():
        return "the derived module is not a file"
    try:
        Path(module_path).relative_to(run_dir / "prefix")
    except ValueError:
        return "the derived module sits outside the prefix"
    return None


def check_cwd_failure_message(tmp):
    missing = _run_check_row(
        "cwd-probe", [sys.executable, "-c", "pass"],
        cwd="@RUN@/no-such-dir")
    run_dir, record = _run_check_leg(tmp, missing)
    if record.get("failure_stage") != "setup":
        return "a missing cwd did not become a setup leg"
    log_text = (run_dir / record["log"]).read_text(
        encoding="utf-8", errors="replace")
    if "cwd not found" not in log_text:
        return f"a missing cwd was reported as: {log_text.strip()[:80]}"
    absent = _run_check_row(
        "binary-probe", ["/nonexistent-journey-binary-xyz"])
    run_dir, record = _run_check_leg(tmp, absent)
    log_text = (run_dir / record["log"]).read_text(
        encoding="utf-8", errors="replace")
    if "binary not found" not in log_text:
        return "a missing binary lost its message"
    return None


def check_setup_exit_null(tmp):
    row = _run_check_row("setup-probe",
                         ["/nonexistent-journey-binary-xyz"])
    _run_dir, record = _run_check_leg(tmp, row)
    if record.get("failure_stage") != "setup":
        return "a missing binary did not become a setup leg"
    if record.get("exit_code") is not None:
        return f"a setup leg recorded exit {record['exit_code']!r}"
    return None


def check_timeout_exit_null(tmp):
    row = _run_check_row(
        "timeout-probe", [sys.executable, "-c",
                           "import time; time.sleep(30)"],
        timeout=1)
    _run_dir, record = _run_check_leg(tmp, row)
    if record.get("failure_stage") != "timeout":
        return "an overrunning leg did not time out"
    if record.get("exit_code") is not None:
        return f"a timeout leg recorded exit {record['exit_code']!r}"
    return None


def check_empty_profile_claims_failure(tmp):
    tmp = Path(tmp)
    table = _empty_profile_table("empty profile probe")
    legs_path = tmp / "legs.json"
    write_json(legs_path, table)
    fake = tmp / "fake"
    (fake / "lib").mkdir(parents=True)
    (fake / "lib" / "libhaskoki.so").write_bytes(b"fake-module-bytes")
    (fake / "toolchain-record.txt").write_text("fake-toolchain\n")
    (fake / "closure").mkdir()
    (fake / "closure" / "review.txt").write_text("fake-review\n")
    ctl = fake / "bin" / "haskoki-ctl"
    ctl.parent.mkdir()
    ctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ctl.chmod(0o755)
    native = tmp / "native"
    native.mkdir()
    fixture = native / "token_fixture"
    fixture.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fixture.chmod(0o755)
    args = _run_check_args(
        tmp, legs_path, module=str(fake / "lib" / "libhaskoki.so"),
        native_dir=str(native))
    with contextlib.redirect_stdout(io.StringIO()):
        rc = run_new(args, table, {}, str(legs_path))
    summary = load_json(tmp / "run" / "summary.json")
    if rc != 1:
        return f"an empty profile run exited {rc}, want 1"
    if summary.get("aggregate") != "fail":
        return "an empty profile run claimed aggregate pass"
    return None


def _spki_cli(tmp, cert_bytes, key_bytes):
    tmp = Path(tmp)
    cert_path = tmp / "spki-cert.der"
    key_path = tmp / "spki-key.der"
    cert_path.write_bytes(cert_bytes)
    key_path.write_bytes(key_bytes)
    return subprocess.run(
        [sys.executable, "-I", str(Path(__file__).resolve()),
         "spki-match", str(cert_path), str(key_path)],
        capture_output=True, text=True, timeout=60)


def _fixture_cert_bytes():
    fixture = find_src_root() / "tests" / "fixtures" / "cert-selfsigned.der"
    try:
        return fixture.read_bytes(), None
    except OSError as exc:
        return None, f"fixture certificate unreadable: {exc}"


def check_spki_pinned_match(tmp):
    cert_bytes, problem = _fixture_cert_bytes()
    if problem is not None:
        return problem
    proc = _spki_cli(tmp, cert_bytes,
                     bytes.fromhex(PINNED_FIXTURE_SPKI_HEX))
    if proc.returncode != 0:
        return ("fixture certificate against its pinned SPKI exited "
                f"{proc.returncode}: "
                f"{(proc.stderr or '').strip()[:120]}")
    if "SPKI-MATCH" not in (proc.stdout or ""):
        return "fixture certificate against its pinned SPKI lacks SPKI-MATCH"
    return None


def check_spki_mismatch(tmp):
    cert_bytes, problem = _fixture_cert_bytes()
    if problem is not None:
        return problem
    proc = _spki_cli(tmp, cert_bytes,
                     bytes.fromhex(FIXED_EC_SPKI_HEX))
    if proc.returncode != 1:
        return (f"RSA certificate against an EC SPKI exited "
                f"{proc.returncode}, want 1")
    lines = (proc.stdout or "").strip().splitlines()
    want = ("SPKI-MISMATCH cert=" + RSA_ENCRYPTION_OID
            + " key=" + EC_PUBLIC_KEY_OID)
    if not lines or lines[0] != want:
        return f"mismatch line {lines[:1]}, want {want!r}"
    return None


def check_spki_truncated(tmp):
    cert_bytes, problem = _fixture_cert_bytes()
    if problem is not None:
        return problem
    proc = _spki_cli(tmp, cert_bytes[:100],
                     bytes.fromhex(PINNED_FIXTURE_SPKI_HEX))
    if proc.returncode != 2:
        return (f"truncated certificate exited {proc.returncode}, "
                "want 2")
    if "SPKI-ERROR" not in (proc.stderr or ""):
        return "truncated certificate lacks the SPKI-ERROR diagnostic"
    return None


def check_probe_provenance(tmp):
    tmp = Path(tmp)
    fake_src = tmp / "fake-src"
    probe_file = fake_src / PROBE_PATH
    probe_file.parent.mkdir(parents=True)
    probe_file.write_bytes(b"tampered probe bytes\n")
    probes = {"java-token-probe": {"path": PROBE_PATH,
                                  "sha256": PROBE_SHA}}
    ctx = _run_check_ctx(tmp)
    ctx["src_root"] = fake_src
    ctx["probes"] = probes
    row = _run_check_row("probe-tampered",
                         [sys.executable, "-c", "pass",
                          "@SRC@/" + PROBE_PATH])
    run_dir, record = _run_check_leg(tmp, row, ctx)
    if record.get("failure_stage") != "setup":
        return "probe bytes differ from provenance but no setup leg resulted"
    try:
        log_text = (run_dir / record["log"]).read_text(
            encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"tampered probe log unreadable: {exc}"
    if "probe provenance mismatch" not in log_text:
        return "tampered probe log lacks the provenance marker"
    ctx_clean = _run_check_ctx(tmp)
    ctx_clean["probes"] = probes
    row_clean = _run_check_row("probe-clean",
                               [sys.executable, "-c", "pass",
                                "@SRC@/" + PROBE_PATH])
    _run_dir, clean = _run_check_leg(tmp, row_clean, ctx_clean)
    if clean.get("status") != "pass":
        return ("clean probe bytes did not pass: "
                f"{clean.get('failure_stage')}")
    table = {
        "$schema": "haskoki-journey-legs/1",
        "clients": {"runner": {"package": None,
                              "package_version": None,
                              "runtime_argv": None,
                              "runtime_version": None}},
        "profiles": {RUN_CHECK_PROFILE: {
            "clients": ["runner"],
            "phases": ["module", "verifier"],
        }},
        "legs": [row, row_clean],
    }
    legs_path = tmp / "probe-legs.json"
    write_json(legs_path, table)
    write_json(run_dir / "summary.json", {
        "$schema": "haskoki-journey-summary/1",
        "profile": RUN_CHECK_PROFILE,
        "required": ["probe-tampered", "probe-clean"],
        "results": {"probe-tampered": "fail", "probe-clean": "pass"},
        "aggregate": "fail",
        "phases_complete": ["module", "verifier"],
        "module_sha256_start": FIXTURE_MODULE_SHA,
        "module_sha256_end": FIXTURE_MODULE_SHA,
        "first_verified_signature": None,
        "client_setup_seconds": None,
        "versions": {},
    })
    failures, _required = check_run(str(run_dir), RUN_CHECK_PROFILE,
                                    str(legs_path))
    observed = {rule for rule, leg, _detail in failures
                if leg == "probe-tampered"}
    if observed != {JR_SETUP}:
        return (f"probe bytes differ from provenance drew "
                f"{sorted(observed)}, want JR-SETUP")
    return None


def run_path_checks():
    """Yield (label, check) for live run-path behavior.

    Each check takes a temp dir and returns None or an error string.
    """
    yield ("substitution expands each token once",
           check_substitute_once)
    yield ("config template substitution expands once",
           check_config_template_once)
    yield ("a directory named token_fixture is refused",
           check_native_fixture_is_file)
    yield ("a leg that orphans a child leaves nothing running",
           check_holder_reaped)
    yield ("a bundle member with an absolute path is refused",
           check_bundle_absolute_member)
    yield ("a bundle member with a .. component is refused",
           check_bundle_dotdot_member)
    yield ("bundle links outside the prefix are refused",
           check_bundle_outside_links)
    yield ("a bundle whose module is a link is refused",
           check_bundle_module_is_regular)
    yield ("a well-formed bundle installs", check_bundle_installs)
    yield ("a missing leg cwd is reported as the cwd",
           check_cwd_failure_message)
    yield ("a setup leg records a null exit", check_setup_exit_null)
    yield ("a timeout leg records a null exit",
           check_timeout_exit_null)
    yield ("an empty profile run claims failure like its verdict",
           check_empty_profile_claims_failure)
    yield ("fixture certificate matches its own SPKI",
           check_spki_pinned_match)
    yield ("RSA certificate against an EC SPKI",
           check_spki_mismatch)
    yield ("truncated certificate", check_spki_truncated)
    yield ("probe bytes differ from provenance",
           check_probe_provenance)


def self_test():
    passed = 0
    checks = list(structural_checks())
    run_checks = list(run_path_checks())
    total = len(SELF_TEST_CASES) + len(checks) + len(run_checks)
    for label, problems in checks:
        if not problems:
            passed += 1
            print(f"  ok: {label}")
        else:
            print(f"  FAIL: {label}: {problems[0][1]}")
    for label, check in run_checks:
        with tempfile.TemporaryDirectory(
                prefix="journeys-runcheck-") as tmp:
            try:
                problem = check(tmp)
            except Exception as exc:
                problem = f"raised {type(exc).__name__}: {exc}"
        if problem is None:
            passed += 1
            print(f"  ok: {label}")
        else:
            print(f"  FAIL: {label}: {problem}")
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
        description="Journey runner and recomputing aggregate check.")
    parser.add_argument("--self-test", action="store_true",
                        help="run the fixture mutation suite")
    sub = parser.add_subparsers(dest="command")
    check = sub.add_parser("check", help="check a run directory")
    check.add_argument("run_dir")
    check.add_argument("--profile", required=True)
    check.add_argument("--legs",
                       default=str(Path(__file__).with_name("legs.json")))
    run = sub.add_parser("run", help="execute legs against a module")
    run.add_argument("--profile", required=True)
    run.add_argument("--out", default=None)
    run.add_argument("--out-existing", default=None)
    run.add_argument("--module", default=None)
    run.add_argument("--bundle-tar", default=None)
    run.add_argument("--native-dir", default=None)
    run.add_argument("--phase", default=None)
    run.add_argument("--legs",
                     default=str(Path(__file__).with_name("legs.json")))
    run.add_argument("--source-sha", default=None)
    run.add_argument("--source-dirty", default=None)
    run.add_argument("--source-dirty-basis", default=None)
    run.add_argument("--client-setup-seconds", default=None)
    run.add_argument("--artifact-image", default=None)
    spki = sub.add_parser("spki-match",
                          help="compare a certificate SPKI with a key SPKI")
    spki.add_argument("cert_der")
    spki.add_argument("spki_der")
    issue = sub.add_parser("issue-cert",
                           help="issue a leaf over a token SPKI")
    issue.add_argument("--pub", required=True)
    issue.add_argument("--out-dir", required=True)
    issue.add_argument("--cn", required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    if args.command == "check":
        return cmd_check(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "spki-match":
        return cmd_spki_match(args)
    if args.command == "issue-cert":
        return cmd_issue_cert(args)
    build_parser().print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
