#!/usr/bin/env python3
"""Shell-helper config contract: the generated backend.toml names the
session's real token path, byte for byte.

The helper serializes the path for Haskoki's TOML subset, which only
decodes backslash-quote, backslash-backslash and backslash-n escapes:
a backslash-u escape would name a different path than the helper's
session directory. Runs the real helper with ASCII and non-ASCII
output dirs and reads back the generated file.

STDLIB ONLY. Run: python3 scripts/test-shell-config.py
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HELPER = REPO / "docker" / "haskoki-shell"


class ShellConfigTests(unittest.TestCase):
    def generated_config(self, out):
        env = dict(os.environ, HASKOKI_DEMO_OUT=str(out),
                   LANG="C.UTF-8", LC_ALL="C.UTF-8")
        env.pop("HASKOKI_CONFIG", None)
        result = subprocess.run(
            ["sh", str(HELPER), "sh", "-c", 'cat "$HASKOKI_CONFIG"'],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(REPO))
        self.assertEqual(result.returncode, 0,
                         result.stderr.decode("utf-8", "replace"))
        return result.stdout

    def session_run(self, out):
        runs = list(out.resolve().glob("session-*"))
        self.assertEqual(len(runs), 1, f"one session dir under {out}")
        return runs[0]

    def test_ascii_out_dir_names_real_token_path(self):
        with tempfile.TemporaryDirectory(prefix="shell-cfg-") as tmp:
            out = Path(tmp) / "plain"
            out.mkdir()
            raw = self.generated_config(out)
            run = self.session_run(out)
            self.assertIn(f'path = "{run}/token.sqlite"'.encode("utf-8"), raw)

    def test_non_ascii_out_dir_round_trips(self):
        with tempfile.TemporaryDirectory(prefix="shell-cfg-") as tmp:
            out = Path(tmp) / "caf\u00e9"
            out.mkdir()
            raw = self.generated_config(out)
            run = self.session_run(out)
            self.assertIn(f'path = "{run}/token.sqlite"'.encode("utf-8"), raw)
            self.assertNotIn(b"\\", raw,
                             "generated config must not escape the path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
