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

    def toml_path_value(self, raw):
        """Decode the path value per Haskoki's TOML subset (see parseStr
        in src/Haskoki/Runtime/Config.hs): only backslash-quote,
        backslash-backslash and backslash-n decode; any other
        backslash stays literal."""
        lines = [line for line in raw.decode("utf-8").splitlines()
                 if line.startswith("path = ")]
        self.assertEqual(len(lines), 1,
                         "one path line in the generated config")
        body = lines[0][len("path = "):].strip()
        self.assertTrue(body.startswith('"') and body.endswith('"'),
                        f"path value is a TOML basic string: {body!r}")
        decode = {'"': '"', "\\": "\\", "n": "\n"}
        out = []
        i, s = 0, body[1:-1]
        while i < len(s):
            if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in decode:
                out.append(decode[s[i + 1]])
                i += 2
            else:
                out.append(s[i])
                i += 1
        return "".join(out)

    def assert_no_unicode_escape(self, raw):
        """The helper must not emit backslash-u escapes: Haskoki's TOML
        subset has no backslash-u decoding, so one would name a
        different path. An escaped backslash followed by u is data,
        not an escape."""
        i = 0
        while i < len(raw):
            if raw[i:i + 1] == b"\\":
                nxt = raw[i + 1:i + 2]
                if nxt == b"u":
                    self.fail("generated config contains a backslash-u escape")
                i += 2 if nxt else 1
            else:
                i += 1

    def test_ascii_out_dir_names_real_token_path(self):
        with tempfile.TemporaryDirectory(prefix="shell-cfg-") as tmp:
            out = Path(tmp) / "plain"
            out.mkdir()
            raw = self.generated_config(out)
            run = self.session_run(out)
            self.assert_no_unicode_escape(raw)
            self.assertEqual(self.toml_path_value(raw), f"{run}/token.sqlite")

    def test_non_ascii_out_dir_round_trips(self):
        with tempfile.TemporaryDirectory(prefix="shell-cfg-") as tmp:
            out = Path(tmp) / "caf\u00e9"
            out.mkdir()
            raw = self.generated_config(out)
            run = self.session_run(out)
            self.assert_no_unicode_escape(raw)
            self.assertEqual(self.toml_path_value(raw), f"{run}/token.sqlite")


if __name__ == "__main__":
    unittest.main(verbosity=2)
