#!/usr/bin/env python3
"""Build-free fixture tests for scripts/release-evidence.sh (V1).

The real runner is copied into a temporary repo fixture with fake
docker/timeout/build commands on PATH, so no container is ever invoked.
Covers: unowned/missing/duplicate drivers, invalid nested parents and
cycles, failed bundle builds (dependent install BLOCKED, independent
drivers still produce evidence), stale archives at the old default path,
and the successful exact-path fresh-archive flow.

Run: python3 scripts/test-release-evidence.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNNER = REPO / "scripts" / "release-evidence.sh"
INVENTORY = REPO / "scripts" / "driver-inventory.json"
INSTALL = REPO / "scripts" / "test-release-install.sh"

VER = "9.9.9-v1"
FAKE_IMAGE = "fake-toolchain:test"
FAKE_IMAGE_ID = "sha256:fake-image-id-v1"
FRESH_MARKER = "fresh-bundle-v1"
STALE_BYTES = b"stale-archive-bytes"

FAKE_DOCKER = """#!/bin/sh
# Fake docker: log every invocation, emulate inspect/run locally.
# Never contacts a real daemon (no docker reference below by design).
echo "docker $*" >> "$FAKE_DOCKER_LOG"
sub="$1"; shift
case "$sub" in
  inspect)
    case "$*" in
      *haskoki-demo*)
        if [ "${FAKE_DEMO_INSPECT_RC:-0}" -ne 0 ]; then
          echo "fake docker: injected demo inspect failure" >&2
          exit 1
        fi;;
    esac
    if [ "${FAKE_INSPECT_RC:-0}" -ne 0 ]; then
      echo "fake docker: injected inspect failure" >&2
      exit 1
    fi
    echo "__FAKE_IMAGE_ID__"
    exit 0
    ;;
  run)
    script=""
    while [ $# -gt 0 ]; do
      case "$1" in
        scripts/*) script="$1"; shift; break;;
        *) shift;;
      esac
    done
    [ -n "$script" ] || { echo "fake docker: no scripts/ command" >&2; exit 99; }
    base=$(basename "$script")
    case " ${FAKE_FAIL_DRIVERS:-} " in
      *" $base "*) echo "fake docker: injected failure for $base" >&2; exit 3;;
    esac
    [ -f "$FIXTURE_ROOT/$script" ] || { echo "fake docker: missing $script" >&2; exit 99; }
    ( cd "$FIXTURE_ROOT" && sh "$script" "$@" )
    exit $?
    ;;
  *)
    echo "fake docker: unsupported subcommand: $sub" >&2
    exit 99
    ;;
esac
"""

FAKE_TIMEOUT = """#!/bin/sh
# Fake timeout: drop flags + duration, exec the rest. Never sleeps.
while [ $# -gt 0 ]; do
  case "$1" in
    -s) shift; [ $# -gt 0 ] && shift;;
    -*) shift;;
    *[!0-9]*|"") break;;
    *) shift; break;;
  esac
done
[ $# -gt 0 ] || { echo "fake timeout: no command" >&2; exit 99; }
exec "$@"
"""

FAKE_MAKE_RELEASE = """#!/bin/sh
# Fake bundle builder, controlled by FAKE_MAKE_RELEASE_RC.
cd "$(dirname "$0")/.." || exit 1
VER=$(grep -m1 '^version:' haskoki.cabal | awk '{print $2}')
OUT="dist-release/haskoki-$VER"
if [ "${FAKE_MAKE_RELEASE_RC:-0}" -ne 0 ]; then
  echo "fake make-release: injected bundle failure"
  exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT/lib" || exit 1
if [ "${FAKE_SKIP_TREE:-0}" = "1" ]; then
  echo "fake make-release: bundle complete but lib missing (injected)"
  exit 0
fi
echo "${FAKE_FRESH_MARKER:-fresh}" > "$OUT/lib/libhaskoki.so"
echo "fake make-release: bundle complete: $OUT"
exit 0
"""

FAKE_INSTALL = """#!/bin/sh
# Fake install leg: records the exact args the runner passed.
{
  echo "install invoked: n=$# explicit=${HASKOKI_REQUIRE_EXPLICIT_ARGS:-unset}"
  echo "arg1=${1-}"
  echo "arg2=${2-}"
  echo "arg3=${3-}"
} >> "$FAKE_INSTALL_ARGS"
[ "${HASKOKI_REQUIRE_EXPLICIT_ARGS:-0}" = "1" ] || { echo "FAIL: runner must set HASKOKI_REQUIRE_EXPLICIT_ARGS=1"; exit 2; }
[ "$#" -eq 3 ] || { echo "FAIL: want exactly 3 explicit args, got $#"; exit 2; }
[ -f "${3-}" ] || { echo "FAIL: tarball missing: ${3-}"; exit 2; }
exit ${FAKE_INSTALL_RC:-0}
"""

STUB_DRIVER = """#!/bin/sh
echo "stub driver $(basename "$0") ok (args: $*)"
exit 0
"""

# The nested onboarding stub trips a marker if the RUNNER ever executes
# it standalone. The fixture parent stub never invokes it, so any marker
# means the runner ran the nested child directly (double pipeline).
STUB_ONBOARDING = """#!/bin/sh
echo "stub driver test-demo-onboarding.sh ok (args: $*)"
touch "$FIXTURE_ROOT/onboarding-direct-run"
exit 0
"""

# Phase-aware demo-image stub: records the phase plus the freeze env the
# runner threaded (image id for test phases, build tag for the build),
# and fails the injected phase (FAKE_DEMO_FAIL_PHASE) with exit 3.
STUB_DEMO_IMAGE = """#!/bin/sh
echo "stub driver test-demo-image.sh ok (phase=${1-} image=${HASKOKI_DEMO_IMAGE:-unset} out=${HASKOKI_DEMO_TEST_OUT:-unset})"
if [ "${1-}" = "${FAKE_DEMO_FAIL_PHASE:-__none__}" ]; then
  echo "stub driver test-demo-image.sh injected failure for phase $1" >&2
  exit 3
fi
exit 0
"""


class Fixture:
    """Temporary repo fixture running the real release-evidence.sh."""

    def __init__(self, test, inventory=None, stubs="inventory",
                 extra_stubs=(), drop_stubs=(), env=None,
                 plant_stale=False):
        self.test = test
        self.tmp = Path(tempfile.mkdtemp(prefix="release-evidence-"))
        self.root = self.tmp / "repo"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "bin").mkdir(parents=True)
        (self.root / "haskoki.cabal").write_text(
            f"cabal-version: 2.4\nname: haskoki-fixture\nversion: {VER}\n")
        shutil.copy(RUNNER, self.root / "scripts" / "release-evidence.sh")
        inv = inventory if inventory is not None else json.loads(INVENTORY.read_text())
        (self.root / "scripts" / "driver-inventory.json").write_text(json.dumps(inv))
        self.inventory = inv
        (self.root / "scripts" / "make-release.sh").write_text(FAKE_MAKE_RELEASE)
        (self.root / "scripts" / "test-release-install.sh").write_text(FAKE_INSTALL)
        (self.root / "bin" / "docker").write_text(
            FAKE_DOCKER.replace("__FAKE_IMAGE_ID__", FAKE_IMAGE_ID))
        (self.root / "bin" / "timeout").write_text(FAKE_TIMEOUT)
        for name in ("docker", "timeout"):
            (self.root / "bin" / name).chmod(0o755)
        if stubs == "inventory":
            names = [d["name"] for d in inv["drivers"]]
        else:
            names = list(stubs)
        names = [n for n in names if n not in drop_stubs]
        names.extend(extra_stubs)
        for name in names:
            if name == "test-release-install.sh":
                continue  # the fake above already owns this path
            if name == "test-demo-onboarding.sh":
                body = STUB_ONBOARDING
            elif name == "test-demo-image.sh":
                body = STUB_DEMO_IMAGE
            else:
                body = STUB_DRIVER
            (self.root / "scripts" / name).write_text(body)
        if plant_stale:
            tree = self.root / "dist-release"
            tree.mkdir(parents=True)
            (tree / f"haskoki-{VER}-linux-x86_64.tar.gz").write_bytes(STALE_BYTES)
        self.env = dict(os.environ)
        self.env.update({
            "PATH": str(self.root / "bin") + os.pathsep + os.environ.get("PATH", ""),
            "HASKOKI_EVIDENCE_DIR": str(self.root / "evidence"),
            "HASKOKI_IMAGE": FAKE_IMAGE,
            "FIXTURE_ROOT": str(self.root),
            "FAKE_DOCKER_LOG": str(self.root / "docker.log"),
            "FAKE_INSTALL_ARGS": str(self.root / "install.args"),
            "FAKE_FRESH_MARKER": FRESH_MARKER,
        })
        self.env.pop("HASKOKI_PROXY_DIR", None)
        if env:
            self.env.update(env)
        self.proc = None

    def run_runner(self):
        self.proc = subprocess.run(
            ["sh", "scripts/release-evidence.sh"], cwd=self.root,
            env=self.env, capture_output=True, text=True, timeout=180)
        return self.proc

    def manifest(self):
        return (self.root / "evidence" / "MANIFEST.txt").read_text()

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = []

    def tearDown(self):
        for fix in self.fixtures:
            fix.cleanup()

    def make(self, **kwargs):
        fix = Fixture(self, **kwargs)
        self.fixtures.append(fix)
        return fix

    def real_inventory(self):
        return json.loads(INVENTORY.read_text())

    def without_driver(self, name):
        inv = self.real_inventory()
        inv["drivers"] = [d for d in inv["drivers"] if d["name"] != name]
        return inv

    # Inventory validation: the unclassified-onboarding shape that broke
    # the old inline-list runner must still fail the manifest loudly.
    def test_unowned_onboarding_driver_fails(self):
        # The stub stays on disk while the inventory drops it: the exact
        # unclassified-onboarding shape that broke the old runner.
        fix = self.make(inventory=self.without_driver("test-demo-onboarding.sh"),
                        extra_stubs=("test-demo-onboarding.sh",))
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("test-demo-onboarding.sh", proc.stdout + proc.stderr)

    def test_missing_inventory_file_fails(self):
        inv = self.real_inventory()
        inv["drivers"].append({"name": "test-ghost.sh", "role": "container", "parent": None})
        fix = self.make(inventory=inv, drop_stubs=("test-ghost.sh",))
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("test-ghost.sh", proc.stdout + proc.stderr)

    def test_duplicate_driver_fails(self):
        inv = self.real_inventory()
        dup = dict(inv["drivers"][-1])
        inv["drivers"].append(dup)
        fix = self.make(inventory=inv)
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("duplicate", (proc.stdout + proc.stderr).lower())

    def test_invalid_nested_parent_fails(self):
        inv = self.real_inventory()
        for d in inv["drivers"]:
            if d["role"] == "nested":
                d["parent"] = "test-ghost.sh"
        fix = self.make(inventory=inv)
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("test-ghost.sh", proc.stdout + proc.stderr)

    def test_nested_cycle_fails(self):
        inv = self.real_inventory()
        inv["drivers"].extend([
            {"name": "test-cycle-a.sh", "role": "nested", "parent": "test-cycle-b.sh"},
            {"name": "test-cycle-b.sh", "role": "nested", "parent": "test-cycle-a.sh"},
        ])
        fix = self.make(inventory=inv,
                        extra_stubs=("test-cycle-a.sh", "test-cycle-b.sh"))
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cycle", (proc.stdout + proc.stderr).lower())

    # A failed bundle build blocks the dependent install, while
    # independent drivers still produce evidence; overall still fails.
    def test_failed_bundle_blocks_install(self):
        fix = self.make(env={"FAKE_MAKE_RELEASE_RC": "1"})
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        manifest = fix.manifest()
        self.assertIn("test-release-install.sh BLOCKED", manifest)
        self.assertIn("archive: none", manifest)
        self.assertFalse((fix.root / "install.args").exists(),
                         "install must not run after bundle failure")
        demo_log = fix.root / "evidence" / "test-demo-image.sh.log"
        self.assertTrue(demo_log.exists(), "independent host driver still runs")
        combined = demo_log.read_text()
        for phase in ("build", "contracts", "full", "compare"):
            self.assertIn(f"phase {phase}: rc=0", combined)
            phase_log = fix.root / "evidence" / "demo-image" / f"{phase}.log"
            self.assertTrue(phase_log.exists(), f"phase log still runs: {phase}")
            self.assertIn(f"stub driver test-demo-image.sh ok (phase={phase} ",
                          phase_log.read_text())
        loader_log = fix.root / "evidence" / "test-loader.sh.log"
        self.assertTrue(loader_log.exists(), "independent container drivers still run")

    # Unverifiable image identity fails closed before any driver runs:
    # no passing manifest without identified images.
    def test_image_identity_required(self):
        fix = self.make(env={"FAKE_INSPECT_RC": "1"})
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("image identity", proc.stdout + proc.stderr)

    # Staging diagnostics must not mutate the already-hashed build log:
    # the manifest hash stays byte-identical to the build log file, and
    # the staging receipt carries the failure instead.
    def test_staging_failure_keeps_build_log_hash(self):
        import hashlib
        import re
        fix = self.make(env={"FAKE_SKIP_TREE": "1"})
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        manifest = fix.manifest()
        self.assertIn("test-release-install.sh BLOCKED", manifest)
        self.assertIn("archive: none", manifest)
        stage_log = fix.root / "evidence" / "stage-archive.log"
        self.assertTrue(stage_log.exists())
        self.assertIn("bundle tree incomplete", stage_log.read_text())
        build_log = fix.root / "evidence" / "make-release.sh.log"
        line = next(line for line in manifest.splitlines()
                    if line.startswith("make-release.sh "))
        logged = re.search(r"log=([0-9a-f]{64})", line)
        self.assertIsNotNone(logged, line)
        self.assertEqual(logged.group(1), hashlib.sha256(build_log.read_bytes()).hexdigest())

    # A stale archive at the old default path is neither used nor
    # overwritten: the runner stages one fresh tarball and passes its
    # exact path to the install leg.
    def test_stale_default_archive_not_used(self):
        fix = self.make(plant_stale=True)
        proc = fix.run_runner()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        stale = fix.root / "dist-release" / f"haskoki-{VER}-linux-x86_64.tar.gz"
        self.assertEqual(stale.read_bytes(), STALE_BYTES, "stale default archive untouched")
        args = (fix.root / "install.args").read_text().splitlines()
        self.assertEqual(args[1], f"arg1={fix.root}/dist-release/haskoki-{VER}")
        tarball = args[3].removeprefix("arg3=")
        self.assertTrue(tarball.startswith(str(fix.root / "evidence" / "staged")),
                        f"install must get the staged tarball, got: {tarball}")
        staged_bytes = Path(tarball).read_bytes()
        self.assertNotEqual(staged_bytes, STALE_BYTES)
        import tarfile
        with tarfile.open(tarball, "r:gz") as tf:
            member = tf.extractfile(f"haskoki-{VER}/lib/libhaskoki.so")
            self.assertIsNotNone(member, "staged tarball lacks the fresh bundle tree")
            self.assertIn(FRESH_MARKER.encode(), member.read())
        manifest = fix.manifest()
        self.assertIn(f"archive: {tarball}", manifest)
        import hashlib
        self.assertIn(f"archive sha256: {hashlib.sha256(staged_bytes).hexdigest()}",
                      manifest)

    # Successful flow: exact paths in, complete manifest out (source SHA,
    # image identity, per-step command/exit/log hash, archive hash), and
    # the nested child never runs standalone.
    def test_successful_flow_records_complete_manifest(self):
        fix = self.make()
        proc = fix.run_runner()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        manifest = fix.manifest()
        self.assertIn("rev: ", manifest)
        self.assertIn(f"image: {FAKE_IMAGE}", manifest)
        self.assertIn(f"image id: {FAKE_IMAGE_ID}", manifest)
        self.assertIn("pass: 19 miss: 0 blocked: 0", manifest)
        for name in ("test-loader.sh", "test-c-abi.sh --negative",
                     "make-release.sh", "test-release-install.sh",
                     "test-demo-image.sh"):
            line = next(line for line in manifest.splitlines()
                        if line.startswith(name + " "))
            self.assertIn("rc=0", line, name)
            self.assertIn("cmd=", line, name)
            self.assertIn("log=", line, name)
        self.assertRegex(manifest, r"archive sha256: [0-9a-f]{64}")
        import hashlib
        import re
        build_line = next(line for line in manifest.splitlines()
                          if line.startswith("make-release.sh "))
        logged = re.search(r"log=([0-9a-f]{64})", build_line)
        self.assertIsNotNone(logged, build_line)
        build_log = fix.root / "evidence" / "make-release.sh.log"
        self.assertEqual(logged.group(1),
                         hashlib.sha256(build_log.read_bytes()).hexdigest())
        nested = [line for line in manifest.splitlines()
                  if line.startswith("test-demo-onboarding.sh ")]
        self.assertEqual(len(nested), 1)
        self.assertIn("NESTED", nested[0])
        self.assertIn("parent=test-demo-image.sh", nested[0])
        self.assertFalse((fix.root / "onboarding-direct-run").exists(),
                         "runner must not execute the nested child standalone")
        docker_log = (fix.root / "docker.log").read_text()
        self.assertNotIn("scripts/test-demo-onboarding.sh", docker_log)

    # The demo-image leg builds once, freezes the inspected image id,
    # and runs the three test phases against it (the CI sharding,
    # serialized): one manifest step, one combined log, per-phase logs
    # and out dirs, each phase under its own 5400s guard.
    def test_demo_image_runs_build_then_frozen_phases(self):
        fix = self.make()
        proc = fix.run_runner()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        ev = fix.root / "evidence"
        combined = (ev / "test-demo-image.sh.log").read_text()
        self.assertIn(f"image id: {FAKE_IMAGE_ID}", combined)
        for phase in ("build", "contracts", "full", "compare"):
            line = next(line for line in combined.splitlines()
                        if line.startswith(f"phase {phase}: "))
            self.assertIn("rc=0", line)
            self.assertRegex(line, r"duration=\d+s")
            self.assertIn(f"log={ev}/demo-image/{phase}.log", line)
        build_log = (ev / "demo-image" / "build.log").read_text()
        self.assertIn(f"(phase=build image=haskoki-demo:{VER} ", build_log)
        self.assertIn(f"out={ev}/demo-image/build)", build_log)
        for phase in ("contracts", "full", "compare"):
            text = (ev / "demo-image" / f"{phase}.log").read_text()
            self.assertIn(f"(phase={phase} image={FAKE_IMAGE_ID} ", text)
            self.assertIn(f"out={ev}/demo-image/{phase})", text)
        manifest = fix.manifest()
        line = next(line for line in manifest.splitlines()
                    if line.startswith("test-demo-image.sh "))
        self.assertIn("PASS", line)
        self.assertIn("rc=0", line)
        for phase in ("build", "contracts", "full", "compare"):
            self.assertIn(f"bash scripts/test-demo-image.sh {phase}", line)
        self.assertIn(f"HASKOKI_DEMO_IMAGE={FAKE_IMAGE_ID}", line)
        self.assertIn("timeout -s KILL 5400", line)

    # A caller-provided build tag (the runbook's unique-tag convention)
    # is what gets built and inspected; test phases still freeze to id.
    def test_demo_image_honors_unique_build_tag(self):
        tag = "haskoki-demo:unique-qual"
        fix = self.make(env={"HASKOKI_DEMO_IMAGE": tag})
        proc = fix.run_runner()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        ev = fix.root / "evidence"
        build_log = (ev / "demo-image" / "build.log").read_text()
        self.assertIn(f"(phase=build image={tag} ", build_log)
        for phase in ("contracts", "full", "compare"):
            text = (ev / "demo-image" / f"{phase}.log").read_text()
            self.assertIn(f"image={FAKE_IMAGE_ID} ", text)

    # A failing middle phase fails the step and later phases are not run.
    def test_failing_middle_phase_fails_step_and_skips_later(self):
        fix = self.make(env={"FAKE_DEMO_FAIL_PHASE": "full"})
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        manifest = fix.manifest()
        line = next(line for line in manifest.splitlines()
                    if line.startswith("test-demo-image.sh "))
        self.assertIn("MISS", line)
        self.assertIn("rc=3", line)
        for phase in ("build", "contracts", "full", "compare"):
            self.assertIn(f"bash scripts/test-demo-image.sh {phase}", line)
        ev = fix.root / "evidence"
        combined = (ev / "test-demo-image.sh.log").read_text()
        self.assertIn("phase build: rc=0", combined)
        self.assertIn("phase contracts: rc=0", combined)
        self.assertIn("phase full: rc=3", combined)
        self.assertIn("phase compare: NOT RUN", combined)
        self.assertFalse((ev / "demo-image" / "compare.log").exists(),
                         "later phases are not run after a failure")
        self.assertIn("pass: 18 miss: 1 blocked: 0", manifest)

    # A failed build runs no test phase and resolves no image id.
    def test_failing_build_phase_skips_tests_and_inspect(self):
        fix = self.make(env={"FAKE_DEMO_FAIL_PHASE": "build"})
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("test-demo-image.sh MISS", fix.manifest())
        combined = (fix.root / "evidence" / "test-demo-image.sh.log").read_text()
        self.assertIn("phase build: rc=3", combined)
        for phase in ("contracts", "full", "compare"):
            self.assertIn(f"phase {phase}: NOT RUN", combined)
            self.assertFalse(
                (fix.root / "evidence" / "demo-image" / f"{phase}.log").exists())
        docker_log = (fix.root / "docker.log").read_text()
        self.assertNotIn("haskoki-demo", docker_log,
                         "no image id is resolved when the build fails")

    # An unresolvable image id fails the step and runs no test phase.
    def test_missing_demo_image_id_fails_step(self):
        fix = self.make(env={"FAKE_DEMO_INSPECT_RC": "1"})
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)
        manifest = fix.manifest()
        self.assertIn("test-demo-image.sh MISS", manifest)
        combined = (fix.root / "evidence" / "test-demo-image.sh.log").read_text()
        self.assertIn("phase build: rc=0", combined)
        self.assertIn("cannot resolve", combined)
        for phase in ("contracts", "full", "compare"):
            self.assertIn(f"phase {phase}: NOT RUN", combined)
            self.assertFalse(
                (fix.root / "evidence" / "demo-image" / f"{phase}.log").exists())

    # Install argument contract (real script, build-free: both cases fail
    # before any docker use).
    # Ruling 3: a role=qualification driver is inventoried (so the
    # drift rule still owns it) but never executed by the manifest: the
    # manifest stays at 19 steps.
    def test_qualification_role_is_skipped_and_manifest_stays_19(self):
        inv = json.loads(INVENTORY.read_text())
        roles = {d["name"]: d["role"] for d in inv["drivers"]}
        self.assertEqual(roles.get("test-ownership-matrix.sh"), "qualification")
        fix = self.make()
        proc = fix.run_runner()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("pass: 19 miss: 0 blocked: 0", fix.manifest())
        self.assertNotIn("test-ownership-matrix.sh", fix.manifest())
        self.assertNotIn("test-ownership-matrix.sh",
                         (fix.root / "docker.log").read_text())

    def test_qualification_driver_with_parent_fails(self):
        inv = json.loads(INVENTORY.read_text())
        for d in inv["drivers"]:
            if d["name"] == "test-ownership-matrix.sh":
                d["parent"] = "test-loader.sh"
        fix = self.make(inventory=inv)
        proc = fix.run_runner()
        self.assertNotEqual(proc.returncode, 0)

    def test_install_contract_requires_explicit_args(self):
        fix = self.make()
        proc = subprocess.run(
            ["sh", str(INSTALL)], cwd=fix.root, capture_output=True, text=True,
            env={**os.environ, "HASKOKI_REQUIRE_EXPLICIT_ARGS": "1"}, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("explicit artifact args required", proc.stdout + proc.stderr)

    def test_install_contract_threads_explicit_paths(self):
        # The real script anchors to its own checkout; explicit relative
        # paths must resolve (and fail loudly) against that root.
        proc = subprocess.run(
            ["sh", str(INSTALL), "custom-tree", "custom-image:test", "custom.tar.gz"],
            cwd=REPO, capture_output=True, text=True,
            env={**os.environ, "HASKOKI_REQUIRE_EXPLICIT_ARGS": "1"}, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        out = proc.stdout + proc.stderr
        self.assertIn(f"artifact missing: {REPO}/custom-tree", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
