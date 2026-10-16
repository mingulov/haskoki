#!/usr/bin/env python3
"""Release nm-gate contract: make-release.sh refuses a hooked tree, and its
hook check fails closed (missing/failing nm, unreadable file, stripped or
empty ELF). Drives the real script through --check-hooks-only.

STDLIB ONLY. Run: python3 scripts/test-release-nm-gate.py
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "make-release.sh"
OSSL_INC = Path("/opt/openssl-4.0.2/include")

PROBE_SO_C = "int nm_gate_probe_anchor;\n"
PROBE_HOOKED_C = "int nm_gate_probe_anchor;\nint hsk_ossl4_test_probe;\n"
PROBE_EXE_C = "int main(void) { return 0; }\n"


def run_script(args, env=None):
    return subprocess.run(
        ["/bin/sh", str(SCRIPT), "--check-hooks-only", *args],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
        cwd=str(REPO))


class NmGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nm-gate-")
        self.work = Path(self.temp.name)
        for tool in ("cc", "nm", "strip"):
            if shutil.which(tool) is None:
                self.fail(f"test tool missing: {tool}")

    def tearDown(self):
        self.temp.cleanup()

    def cc(self, src, out, *flags):
        c = self.work / "probe.c"
        c.write_text(src)
        r = subprocess.run(["cc", *flags, "-o", str(out), str(c)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
        self.assertEqual(r.returncode, 0, f"cc failed: {r.stdout}")
        return out

    def test_clean_pair_passes(self):
        so = self.cc(PROBE_SO_C, self.work / "probe.so", "-shared", "-fPIC")
        exe = self.cc(PROBE_EXE_C, self.work / "probe-exe")
        r = run_script([str(so), "nm_gate_probe_anchor", str(exe), "main"])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("PASS", r.stdout)

    def test_hooked_shared_object_is_refused(self):
        so = self.cc(PROBE_HOOKED_C, self.work / "hooked.so", "-shared", "-fPIC")
        r = run_script([str(so), "nm_gate_probe_anchor"])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("test-hook symbols", r.stdout)

    def test_hooks_configured_shim_object_is_refused(self):
        # Negative control against the real object: the hooks-configured
        # shim is refused for its hooks (the message proves the reason),
        # while the production-configured one passes.
        if not (OSSL_INC / "openssl" / "evp.h").is_file():
            self.fail("pinned OpenSSL 4 headers missing")
        flags = ["-std=c11", "-Icbits", f"-I{OSSL_INC}"]
        for obj, define in (("prod.o", []), ("hooks.o", ["-DHSK_OSSL4_TEST_HOOKS"])):
            r = subprocess.run(
                ["cc", *flags, *define, "-c", "-o", str(self.work / obj),
                 str(REPO / "cbits" / "ossl4_ctx.c")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                cwd=str(REPO))
            self.assertEqual(r.returncode, 0, f"shim compile failed: {r.stdout}")
        r = run_script([str(self.work / "prod.o"), "hsk_ossl4_dh_derive"])
        self.assertEqual(r.returncode, 0, r.stdout)
        r = run_script([str(self.work / "hooks.o"), "hsk_ossl4_test_seam_reset"])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("test-hook symbols", r.stdout)

    def test_missing_nm_is_refused(self):
        so = self.cc(PROBE_SO_C, self.work / "probe.so", "-shared", "-fPIC")
        bindir = self.work / "nobin"
        bindir.mkdir()
        for tool in ("dirname", "grep", "cat", "rm"):
            p = shutil.which(tool)
            self.assertIsNotNone(p, f"host tool missing: {tool}")
            (bindir / tool).symlink_to(p)
        env = dict(os.environ, PATH=str(bindir))
        r = run_script([str(so), "nm_gate_probe_anchor"], env=env)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("nm not found", r.stdout)

    def test_failing_nm_is_refused(self):
        so = self.cc(PROBE_SO_C, self.work / "probe.so", "-shared", "-fPIC")
        bindir = self.work / "badbin"
        bindir.mkdir()
        fake = bindir / "nm"
        fake.write_text("#!/bin/sh\necho 'nm: boom' >&2\nexit 1\n")
        fake.chmod(0o755)
        for tool in ("dirname", "grep", "cat", "rm"):
            (bindir / tool).symlink_to(shutil.which(tool))
        env = dict(os.environ, PATH=str(bindir))
        r = run_script([str(so), "nm_gate_probe_anchor"], env=env)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("nm failed", r.stdout)

    def test_unreadable_file_is_refused(self):
        missing = self.work / "no-such-file.so"
        r = run_script([str(missing), "nm_gate_probe_anchor"])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("cannot read", r.stdout)

    def test_stripped_elf_is_refused(self):
        exe = self.cc(PROBE_EXE_C, self.work / "probe-exe")
        r = subprocess.run(["strip", str(exe)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
        self.assertEqual(r.returncode, 0, f"strip failed: {r.stdout}")
        r = run_script([str(exe), "main"])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertNotIn("PASS", r.stdout)

    def test_empty_file_is_refused(self):
        empty = self.work / "empty.so"
        empty.write_bytes(b"")
        r = run_script([str(empty), "nm_gate_probe_anchor"])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertNotIn("PASS", r.stdout)

    def test_gate_construction_is_pinned(self):
        src = SCRIPT.read_text()
        self.assertIn("nm -D", src, "shared objects must be examined with nm -D")
        self.assertIn("command -v nm", src, "a missing nm must fail the gate")
        self.assertIn("C_GetFunctionList", src, "the module listing needs its anchor")
        self.assertIn("hs_main", src, "the ctl listing needs its anchor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
