#!/usr/bin/env python3
"""Release nm-gate contract: make-release.sh refuses a hooked tree, and its
hook check fails closed (missing/failing nm, unreadable file, stripped or
empty ELF). Drives the real script through --check-hooks-only.

STDLIB ONLY. Run: python3 scripts/test-release-nm-gate.py
Direct host runs need cc, nm and strip. The real-shim leg compiles
against the pinned OpenSSL 4 headers at /opt/openssl-4.0.2/include
when present, else inside the selected builder image (HASKOKI_IMAGE,
default haskoki-dev:ghc-9.10.3) via docker; it fails closed when
neither is available.
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
BUILDER_IMAGE = "haskoki-dev:ghc-9.10.3"
DOCKER_TIMEOUT = 600

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

    def builder_image(self):
        """Selected builder image; empty or missing selects the default,
        matching the shell drivers' ${HASKOKI_IMAGE:-default}."""
        return os.environ.get("HASKOKI_IMAGE") or BUILDER_IMAGE

    def builder_probe_cmd(self, image=None):
        image = image or self.builder_image()
        return ["docker", "run", "--rm", "--network", "host", image,
                "test", "-r", f"{OSSL_INC}/openssl/evp.h"]

    def probe_builder_headers(self):
        image = self.builder_image()
        try:
            r = subprocess.run(
                self.builder_probe_cmd(image),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=DOCKER_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            self.fail(f"builder header probe timed out: {e}")
        self.assertEqual(r.returncode, 0,
                         f"pinned OpenSSL 4 headers missing in builder {image}")

    def shim_compile_cmd(self, obj, define, inc=OSSL_INC):
        """Host cc when the pinned headers exist, else builder cc.

        The Docker-route contributor has no host OpenSSL install: the
        header-dependent compile falls back to the selected builder
        image (HASKOKI_IMAGE, default haskoki-dev:ghc-9.10.3). Fails
        closed when neither is available; never skips.
        """
        flags = ["-std=c11", "-Icbits", f"-I{inc}"]
        if (inc / "openssl" / "evp.h").is_file():
            return (["cc", *flags, *define, "-c", "-o", str(self.work / obj),
                     str(REPO / "cbits" / "ossl4_ctx.c")], str(REPO))
        image = self.builder_image()
        if shutil.which("docker") is None:
            self.fail("pinned OpenSSL 4 headers missing "
                      "and no docker builder available")
        # Inside the builder the prefix is pinned, regardless of the
        # host probe path that selected this branch.
        builder_flags = ["-std=c11", "-Icbits", f"-I{OSSL_INC}"]
        return (["docker", "run", "--rm", "--network", "host",
                 "-v", f"{REPO}:/work", "-v", f"{self.work}:/out",
                 "-w", "/work", image,
                 "cc", *builder_flags, *define, "-c", "-o", f"/out/{obj}",
                 "cbits/ossl4_ctx.c"], str(REPO))

    def compile_shim(self, obj, define, inc=OSSL_INC):
        # Same branch as shim_compile_cmd: without host headers the
        # compile runs in the builder, so prove the pinned prefix
        # exists there first. Without the probe cc would silently fall
        # back to the image's system headers.
        if not (inc / "openssl" / "evp.h").is_file():
            self.probe_builder_headers()
        cmd, cwd = self.shim_compile_cmd(obj, define, inc=inc)
        try:
            r = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd, timeout=DOCKER_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            self.fail(f"shim compile timed out: {e}")
        self.assertEqual(r.returncode, 0, f"shim compile failed: {r.stdout}")

    def test_hooks_configured_shim_object_is_refused(self):
        # Negative control against the real object: the hooks-configured
        # shim is refused for its hooks (the message proves the reason),
        # while the production-configured one passes.
        for obj, define in (("prod.o", []), ("hooks.o", ["-DHSK_OSSL4_TEST_HOOKS"])):
            self.compile_shim(obj, define)
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

    def test_shim_compile_uses_host_cc_when_headers_present(self):
        inc = self.work / "prefix" / "include"
        (inc / "openssl").mkdir(parents=True)
        (inc / "openssl" / "evp.h").write_text("")
        cmd, cwd = self.shim_compile_cmd("prod.o", [], inc=inc)
        self.assertEqual(cmd[0], "cc")
        self.assertNotIn("docker", cmd)
        self.assertIn(f"-I{inc}", cmd)

    def test_shim_compile_uses_builder_when_headers_missing(self):
        bindir = self.work / "with-docker"
        bindir.mkdir()
        fake = bindir / "docker"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        old_path, old_image = os.environ.get("PATH"), os.environ.get("HASKOKI_IMAGE")
        try:
            os.environ["PATH"] = str(bindir)
            os.environ["HASKOKI_IMAGE"] = "custom-builder:test"
            cmd, cwd = self.shim_compile_cmd(
                "hooks.o", ["-DHSK_OSSL4_TEST_HOOKS"],
                inc=self.work / "no-such-prefix")
        finally:
            self.restore_env("PATH", old_path)
            self.restore_env("HASKOKI_IMAGE", old_image)
        self.assertEqual(cmd[:5], ["docker", "run", "--rm", "--network", "host"])
        self.assertIn("custom-builder:test", cmd)
        self.assertIn("-DHSK_OSSL4_TEST_HOOKS", cmd)
        self.assertIn("/out/hooks.o", cmd)
        self.assertIn(f"-I{OSSL_INC}", cmd)

    def test_shim_compile_defaults_to_canonical_builder(self):
        bindir = self.work / "with-docker"
        bindir.mkdir()
        (bindir / "docker").write_text("#!/bin/sh\nexit 0\n")
        (bindir / "docker").chmod(0o755)
        for image in (None, ""):
            with self.subTest(image=image):
                old_path = os.environ.get("PATH")
                old_image = os.environ.get("HASKOKI_IMAGE")
                try:
                    os.environ["PATH"] = str(bindir)
                    if image is None:
                        os.environ.pop("HASKOKI_IMAGE", None)
                    else:
                        os.environ["HASKOKI_IMAGE"] = image
                    cmd, cwd = self.shim_compile_cmd(
                        "prod.o", [], inc=self.work / "no-such-prefix")
                finally:
                    self.restore_env("PATH", old_path)
                    self.restore_env("HASKOKI_IMAGE", old_image)
                self.assertIn("haskoki-dev:ghc-9.10.3", cmd)

    def test_builder_probe_cmd_uses_selected_image(self):
        for image, want in (("custom-builder:test", "custom-builder:test"),
                            ("", BUILDER_IMAGE), (None, BUILDER_IMAGE)):
            with self.subTest(image=image):
                old = os.environ.get("HASKOKI_IMAGE")
                try:
                    if image is None:
                        os.environ.pop("HASKOKI_IMAGE", None)
                    else:
                        os.environ["HASKOKI_IMAGE"] = image
                    cmd = self.builder_probe_cmd()
                finally:
                    self.restore_env("HASKOKI_IMAGE", old)
                self.assertEqual(cmd[:6], ["docker", "run", "--rm",
                                           "--network", "host", want])
                self.assertEqual(cmd[6:], ["test", "-r",
                                           f"{OSSL_INC}/openssl/evp.h"])

    def test_builder_probe_refuses_image_without_pinned_headers(self):
        bindir = self.work / "probe-fails"
        bindir.mkdir()
        fake = bindir / "docker"
        fake.write_text("#!/bin/sh\nexit 1\n")
        fake.chmod(0o755)
        old_path = os.environ.get("PATH")
        try:
            os.environ["PATH"] = str(bindir)
            with self.assertRaises(AssertionError) as ctx:
                self.probe_builder_headers()
        finally:
            self.restore_env("PATH", old_path)
        self.assertIn("missing in builder", str(ctx.exception))

    def test_builder_plan_runs_probe_before_compile(self):
        bindir = self.work / "probe-passes"
        bindir.mkdir()
        fake = bindir / "docker"
        fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PROBE_LOG\"\nexit 0\n")
        fake.chmod(0o755)
        probe_log = self.work / "docker.log"
        old_path = os.environ.get("PATH")
        old_image = os.environ.get("HASKOKI_IMAGE")
        old_log = os.environ.get("PROBE_LOG")
        try:
            os.environ["PATH"] = str(bindir)
            os.environ["HASKOKI_IMAGE"] = "custom-builder:test"
            os.environ["PROBE_LOG"] = str(probe_log)
            self.compile_shim("prod.o", [], inc=self.work / "no-such-prefix")
        finally:
            self.restore_env("PATH", old_path)
            self.restore_env("HASKOKI_IMAGE", old_image)
            self.restore_env("PROBE_LOG", old_log)
        lines = probe_log.read_text().splitlines()
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("test -r", lines[0])
        self.assertIn("/opt/openssl-4.0.2/include/openssl/evp.h", lines[0])
        self.assertIn("cc -std=c11", lines[1])
        self.assertIn("custom-builder:test", lines[0])
        self.assertIn("custom-builder:test", lines[1])

    def test_shim_compile_fails_closed_without_headers_or_docker(self):
        bindir = self.work / "no-docker"
        bindir.mkdir()
        old_path = os.environ.get("PATH")
        try:
            os.environ["PATH"] = str(bindir)
            with self.assertRaises(AssertionError) as ctx:
                self.shim_compile_cmd(
                    "prod.o", [], inc=self.work / "no-such-prefix")
        finally:
            self.restore_env("PATH", old_path)
        self.assertIn("headers missing", str(ctx.exception))

    def restore_env(self, name, value):
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


if __name__ == "__main__":
    unittest.main(verbosity=2)
