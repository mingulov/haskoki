#!/usr/bin/env python3
"""Build-free negative controls for scripts/test-ownership-matrix.sh.

The driver is run against fake tasty binaries (HASKOKI_OWN_BIN_DIR), so
nothing here builds or needs a toolchain. Every control that must fail
asserts a nonzero exit AND that no cabal build was attempted when the
failure is an argument-validation one.
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
DRIVER = REPO / "scripts" / "test-ownership-matrix.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"

FAKE_BIN = """#!/bin/sh
# Fake tasty binary: behaviour selected by FAKE_* env.
n=""
list=0
prev=""
for a in "$@"; do
  case "$a" in
    --list-tests) list=1;;
    -N*) n="${a#-N}";;
  esac
done
# Emulate tasty: without -j <n> it bumps capabilities to the processor count.
case " $* " in
  *" -j "*) ;;
  *) [ -z "${FAKE_TASTY_BUMP:-}" ] || n=12;;
esac
if [ "$list" = 1 ]; then
  i=0
  while [ "$i" -lt "${FAKE_LISTED:-200}" ]; do
    echo "root.group.test $i"; i=$((i + 1))
  done
  exit 0
fi
if [ -z "${FAKE_NO_USING:-}" ]; then
  echo "TASKS: 4 (1 bound, 3 peak workers (3 total), using -N${FAKE_USING:-$n})" >&2
fi
# Emits only when the driver sets HASKOKI_OWNERSHIP_COUNTERS=1 (ruling 5).
# FAKE_CASES (a tsv: pattern, case id, comma labels; built from the real
# case table) says which case this -p pattern is and which labels to print.
if [ -n "${FAKE_COUNTER:-}" ] && [ "${HASKOKI_OWNERSHIP_COUNTERS:-}" = 1 ]; then
  pat=""; prev=""
  for a in "$@"; do
    [ "$prev" != -p ] || pat="$a"
    prev="$a"
  done
  row=$(awk -F'\t' -v p="$pat" '$1 == p { print $2 "\t" $3 }' "$FAKE_CASES")
  c=${row%%	*}; labels=${row#*	}
  [ -z "${FAKE_COUNTER_CASE:-}" ] || c="$FAKE_COUNTER_CASE"
  first=1
  for l in $(printf '%s' "$labels" | tr ',' ' ') ${FAKE_EXTRA:-}; do
    [ "$l" != "${FAKE_DROP:-}" ] || continue
    v=0
    [ "$first" != 1 ] || v=${FAKE_COUNTER_VAL:-0}
    first=0
    printf 'some test name: '   # tasty may leave the name on the line
    echo "OWNERSHIP-COUNTERS case=$c test=$l bufs=0 digests=$v envs=0"
  done
fi
if [ "${FAKE_RC:-0}" -ne 0 ]; then
  echo "1 out of ${FAKE_LISTED:-200} tests failed"
  exit "${FAKE_RC}"
fi
echo "All ${FAKE_PASSED:-${FAKE_LISTED:-200}} tests passed (0.01s)"
exit 0
"""

FAKE_CABAL = """#!/bin/sh
echo "cabal $*" >> "$FAKE_CABAL_LOG"
exit 99
"""


def case_table():
    """Parse the driver's own case table (the heredoc) into rows."""
    text = DRIVER.read_text()
    body = text.split("<<'TABLE'\n", 1)[1].split("\nTABLE\n", 1)[0]
    rows = []
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split("|")
        assert len(f) == 6, line
        rows.append(dict(case=f[0], suite=f[1], pat=f[2], min=int(f[3]),
                         status=f[4], counters=f[5]))
    return rows


ACTIVE = [r for r in case_table() if r["status"] == "active"]
GATED = [r for r in ACTIVE if r["counters"] != "no"]


class DriverControls(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="own-matrix-"))
        self.bins = self.tmp / "bins"
        self.fakepath = self.tmp / "path"
        self.out = self.tmp / "receipts"
        self.bins.mkdir()
        self.fakepath.mkdir()
        for name in ("haskoki-model-tests", "haskoki-engine-tests",
                     "haskoki-storage-tests"):
            (self.bins / name).write_text(FAKE_BIN)
            (self.bins / name).chmod(0o755)
        (self.fakepath / "cabal").write_text(FAKE_CABAL)
        (self.fakepath / "cabal").chmod(0o755)
        self.cabal_log = self.tmp / "cabal.log"
        self.cases = self.tmp / "fake-cases.tsv"
        self.cases.write_text("".join(
            f"{r['pat']}\t{r['case']}\t{r['counters'] if r['counters'] != 'no' else ''}\n"
            for r in ACTIVE))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_driver(self, fake_bins=True, **env):
        e = dict(os.environ)
        e["PATH"] = str(self.fakepath) + os.pathsep + e["PATH"]
        e["FAKE_CABAL_LOG"] = str(self.cabal_log)
        e["FAKE_CASES"] = str(self.cases)
        e["HASKOKI_OWN_SHA"] = SHA
        e["HASKOKI_OWN_RECEIPTS"] = str(self.out)
        if fake_bins:
            e["HASKOKI_OWN_BIN_DIR"] = str(self.bins)
        e.update({k: str(v) for k, v in env.items()})
        return subprocess.run(["sh", str(DRIVER)], cwd=REPO, env=e,
                              capture_output=True, text=True, timeout=120)

    def receipts(self):
        return sorted(self.out.glob("*.json")) if self.out.exists() else []

    def no_build(self):
        self.assertFalse(self.cabal_log.exists(), "cabal was invoked")

    # ---- must fail before any build ----
    def test_rts_n3_rejected_before_build(self):
        p = self.run_driver(fake_bins=False, HASKOKI_OWN_RTS="3")
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("HASKOKI_OWN_RTS", p.stdout + p.stderr)
        self.no_build()
        self.assertEqual(self.receipts(), [])

    def test_rts_list_with_one_bad_value_rejected(self):
        p = self.run_driver(fake_bins=False, HASKOKI_OWN_RTS="1 N3")
        self.assertNotEqual(p.returncode, 0)
        self.no_build()

    def test_unknown_case_rejected_before_build(self):
        p = self.run_driver(fake_bins=False, HASKOKI_OWN_CASE="bogus")
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("HASKOKI_OWN_CASE", p.stdout + p.stderr)
        self.no_build()

    def test_pending_case_cannot_be_selected(self):
        p = self.run_driver(fake_bins=False, HASKOKI_OWN_CASE="wp07-pending")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("pending", p.stdout + p.stderr)
        self.no_build()

    def test_bad_sha_rejected_before_build(self):
        p = self.run_driver(fake_bins=False, HASKOKI_OWN_SHA="nothex")
        self.assertNotEqual(p.returncode, 0)
        self.no_build()

    # ---- must fail after listing/running, never vacuously pass ----
    # ---- ownership counters (Task 4) ----
    def test_counter_line_missing_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate")
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("counter line missing", p.stdout)
        d = json.loads((self.out / "m2-lifetime-gate.N1.json").read_text())
        self.assertEqual((d["status"], d["counters_required"]), ("fail", True))

    def test_counter_line_missing_fails_for_native_transfers(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m1-native-transfers")
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("counter line missing", p.stdout)

    def test_nonzero_counter_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_COUNTER=1,
                            FAKE_COUNTER_VAL=1)
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("counter nonzero: digests=1", p.stdout)

    def test_counter_line_for_another_case_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_COUNTER=1,
                            FAKE_COUNTER_CASE="m1-native-transfers")
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("another case", p.stdout)

    def test_counters_not_required_for_other_cases(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lease-protocol")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        d = json.loads((self.out / "m2-lease-protocol.N1.json").read_text())
        self.assertEqual((d["counters_required"], d["counters"]), (False, []))

    def test_receipt_records_tree_clean_boolean(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lease-protocol", HASKOKI_OWN_RTS="1")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        d = json.loads((self.out / "m2-lease-protocol.N1.json").read_text())
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                                    capture_output=True, text=True).stdout.strip())
        self.assertIs(d["tree_clean"], not dirty)

    def test_min_count_floor_holds_for_every_case_in_the_table(self):
        # A shrinking suite fails: for EVERY active case parsed from
        # the driver's table, one test fewer than the floor fails and
        # exactly the floor passes. (Floors are the real-run counts.)
        self.assertGreaterEqual(len(ACTIVE), 17)
        for r in ACTIVE:
            with self.subTest(case=r["case"]):
                self.assertGreaterEqual(r["min"], 1)
                low = self.run_driver(HASKOKI_OWN_CASE=r["case"], HASKOKI_OWN_RTS="1",
                                      FAKE_LISTED=r["min"] - 1, FAKE_COUNTER=1)
                self.assertNotEqual(low.returncode, 0, low.stdout)
                want = ("matched 0 tests" if r["min"] == 1
                        else f"matched {r['min'] - 1} tests, minimum {r['min']}")
                self.assertIn(want, low.stdout)
                ok = self.run_driver(HASKOKI_OWN_CASE=r["case"], HASKOKI_OWN_RTS="1",
                                     FAKE_LISTED=r["min"], FAKE_COUNTER=1)
                self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

    def test_gated_cases_table_data(self):
        # Gated cases carry an explicit, duplicate-free label list.
        names = {r["case"] for r in GATED}
        for want in ("m1-native-transfers", "m2-lifetime-gate", "m3-handle-registry",
                     "m3-ffi-acquisition", "m3-async-engine"):
            self.assertIn(want, names)
        for r in GATED:
            labels = r["counters"].split(",")
            self.assertEqual(len(labels), len(set(labels)), r["case"])
            self.assertTrue(all(l for l in labels), r["case"])

    def test_dropping_one_tests_emission_fails_every_gated_case(self):
        for r in GATED:
            for lbl in r["counters"].split(","):
                with self.subTest(case=r["case"], label=lbl):
                    p = self.run_driver(HASKOKI_OWN_CASE=r["case"], HASKOKI_OWN_RTS="1",
                                        FAKE_COUNTER=1, FAKE_DROP=lbl)
                    self.assertNotEqual(p.returncode, 0, p.stdout)
                    # Dropping the only label leaves no line at all.
                    want = ("counter line missing" if "," not in r["counters"]
                            else f"counter label missing: {lbl}")
                    self.assertIn(want, p.stdout)

    def test_unexpected_label_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m3-handle-registry", HASKOKI_OWN_RTS="1",
                            FAKE_COUNTER=1, FAKE_EXTRA="stowaway")
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("unexpected counter label: stowaway", p.stdout)

    def test_zero_match_pattern_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_LISTED=0)
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("matched 0", p.stdout + p.stderr)
        self.assertTrue(all(json.loads(r.read_text())["status"] == "fail"
                            for r in self.receipts()))

    def test_listed_below_minimum_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_LISTED=1)
        self.assertNotEqual(p.returncode, 0, p.stdout)

    def test_ignored_rts_flag_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_NO_USING=1)
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("using -N", p.stdout + p.stderr)

    def test_wrong_rts_evidence_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", HASKOKI_OWN_RTS="4",
                            FAKE_USING=2)
        self.assertNotEqual(p.returncode, 0, p.stdout)

    def test_passed_count_mismatch_fails(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_PASSED=2)
        self.assertNotEqual(p.returncode, 0, p.stdout)

    def test_failing_run_fails_and_still_writes_receipt(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_RC=1)
        self.assertNotEqual(p.returncode, 0, p.stdout)
        rs = self.receipts()
        self.assertEqual(len(rs), 3)
        self.assertTrue(all(json.loads(r.read_text())["rc"] == 1 for r in rs))

    # ---- positive ----
    def test_one_case_three_receipts(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_COUNTER=1)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        names = [r.name for r in self.receipts()]
        self.assertEqual(names, ["m2-lifetime-gate.N1.json", "m2-lifetime-gate.N2.json",
                                 "m2-lifetime-gate.N4.json"])
        for r in self.receipts():
            d = json.loads(r.read_text())
            self.assertEqual(d["sha"], SHA)
            self.assertEqual((d["listed"], d["passed"], d["rc"], d["status"]),
                             (200, 200, 0, "pass"))
            self.assertEqual(d["using_n"], d["rts_n"])
            self.assertEqual(len(d["binary_sha256"]), 64)
            self.assertIn("nproc", d)
            self.assertIn("duration_s", d)
            self.assertEqual(d["counters"], [
                f"OWNERSHIP-COUNTERS case=m2-lifetime-gate test={l} bufs=0 digests=0 envs=0"
                for l in next(r["counters"] for r in ACTIVE
                              if r["case"] == "m2-lifetime-gate").split(",")])
            self.assertIs(d["counters_required"], True)

    def test_tasty_capability_bump_is_prevented_by_jobs_flag(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", FAKE_TASTY_BUMP=1,
                            FAKE_COUNTER=1)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_rts_subset(self):
        p = self.run_driver(HASKOKI_OWN_CASE="m2-lifetime-gate", HASKOKI_OWN_RTS="2",
                            FAKE_COUNTER=1)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual([r.name for r in self.receipts()], ["m2-lifetime-gate.N2.json"])

    def test_full_table_runs_every_nonpending_case_and_lists_pending(self):
        p = self.run_driver(FAKE_COUNTER=1)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("PENDING wp07-pending", p.stdout)
        ids = {json.loads(r.read_text())["case"] for r in self.receipts()}
        self.assertNotIn("wp07-pending", ids)
        self.assertEqual(len(self.receipts()), 3 * len(ids))
        self.assertTrue((self.out / "index.tsv").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=1)
