#!/usr/bin/env python3
"""Focused release workflow contract, without a YAML package dependency."""
import ast
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"


def section(text, name, indent):
    match = re.search(rf"^{' ' * indent}{re.escape(name)}:\s*\n", text, re.M)
    if not match:
        raise AssertionError(f"missing section: {name}")
    tail = text[match.end():]
    end = re.search(rf"^\S|^ {{1,{indent}}}\S", tail, re.M) if indent else re.search(r"^\S", tail, re.M)
    return tail[:end.start()] if end else tail


def field(text, name, indent):
    match = re.search(rf"^{' ' * indent}{re.escape(name)}: (.+)$", text, re.M)
    if not match:
        raise AssertionError(f"missing field: {name}")
    return match[1]


def evaluate(expression, event, ref, mode, framework=""):
    expression = expression.removeprefix("${{ ").removesuffix(" }}")
    for name, value in [("github.event.inputs.framework_ref", framework),
                        ("github.event_name", event), ("github.ref", ref), ("inputs.mode", mode)]:
        expression = expression.replace(name, repr(value))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", "not ", expression).strip()
    tree = ast.parse(expression, mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Not, ast.And, ast.Or,
               ast.Compare, ast.Eq, ast.Constant, ast.Call, ast.Name, ast.Load)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError("unsupported release expression")
    return eval(compile(tree, "workflow-expression", "eval"), {"__builtins__": {}},
                {"startsWith": lambda value, prefix: value.startswith(prefix),
                 "format": lambda pattern, value: pattern.format(value)})


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.jobs = section(self.text, "jobs", 0)
        self.publish = section(self.jobs, "publish", 2)

    def test_build_dispatch_and_normal_ci_cannot_publish_or_cancel_releases(self):
        concurrency = section(self.text, "concurrency", 0)
        for event, ref, mode, want_release in [
            ("push", "refs/heads/main", "", False),
            ("pull_request", "refs/pull/11/merge", "", False),
            ("workflow_dispatch", "refs/heads/main", "build", False),
            ("workflow_dispatch", "refs/tags/v0.3.0.0", "build", False),
            ("workflow_dispatch", "refs/heads/main", "release", True),
            ("push", "refs/tags/v0.3.0.0", "", True),
        ]:
            with self.subTest(event=event, ref=ref, mode=mode):
                self.assertEqual(bool(evaluate(field(self.publish, "if", 4), event, ref, mode)), want_release)
                self.assertEqual(evaluate(field(concurrency, "group", 2), event, ref, mode),
                                 "haskoki-publication" if want_release else f"ci-{ref}")
                self.assertEqual(evaluate(field(concurrency, "cancel-in-progress", 2), event, ref, mode),
                                 not want_release)

    def test_publish_requires_all_existing_gates_and_preflight(self):
        needs = set(ast.literal_eval(re.sub(r"([a-z][a-z0-9-]*)", r"'\1'", field(self.publish, "needs", 4))))
        self.assertTrue({"release-request", "haskell", "bundle", "c-drivers", "pkcs11-fast", "demo-image"} <= needs)
        for job in ["haskell", "c-drivers", "bundle", "fetch-data"]:
            self.assertEqual(field(section(self.jobs, job, 2), "needs", 4), "release-request")

    def test_demo_gate_always_runs_and_requires_build_and_all_shards(self):
        build = section(self.jobs, "demo-image-build", 2)
        shards = section(self.jobs, "demo-image-shards", 2)
        gate = section(self.jobs, "demo-image", 2)
        self.assertEqual(field(build, "needs", 4), "bundle")
        self.assertEqual(field(shards, "needs", 4), "demo-image-build")
        self.assertEqual(field(gate, "needs", 4), "[demo-image-build, demo-image-shards]")
        self.assertEqual(field(gate, "if", 4), "${{ always() }}")
        strategy = section(shards, "strategy", 4)
        self.assertEqual(field(strategy, "fail-fast", 6), "false")
        self.assertEqual(field(strategy, "max-parallel", 6), "3")
        self.assertEqual(field(section(strategy, "matrix", 6), "phase", 8),
                         "[contracts, full, compare]")
        self.assertIn("needs.demo-image-build.result", gate)
        self.assertIn("needs.demo-image-shards.result", gate)
        self.assertIn("demo-image-shards.py check-results", gate)
        self.assertIn("demo-image-shards.py gate", gate)
        self.assertLess(gate.index("check-results"), gate.index("actions/download-artifact"))
        self.assertLess(gate.index("demo-image-shards.py gate"), gate.index("cp candidate/demo-image.tar.gz"))
        self.assertNotIn("docker build", shards + gate)
        self.assertNotIn("docker save", shards + gate)
        self.assertIn("sh scripts/test-demo-image.sh build", build)
        self.assertIn('sh scripts/test-demo-image.sh "${{ matrix.phase }}"', shards)
        self.assertIn("demo-image-shards.py verify-archive", shards)
        self.assertLess(shards.index("verify-archive"), shards.index("docker load"))
        for artifact in ["demo-image-tested", "demo-image-runs"]:
            self.assertIn("name: " + artifact, gate)
        for output in ["imageid", "configid", "base_digest", "rust_digest"]:
            self.assertIn(output + ": ${{ steps.gate.outputs." + output + " }}", gate)

    def test_only_publication_job_has_write_permissions(self):
        self.assertEqual(field(section(self.text, "permissions", 0), "contents", 2), "read")
        for job in re.findall(r"(?m)^  ([a-z][a-z0-9-]*):", self.jobs):
            if job != "publish":
                self.assertNotRegex(section(self.jobs, job, 2), r"(?m)^\s+[a-z-]+: write$", "write outside publication")
        permissions = section(self.publish, "permissions", 4)
        self.assertEqual(field(permissions, "actions", 6), "read")
        for name in ["contents", "packages", "attestations", "id-token"]:
            self.assertEqual(field(permissions, name, 6), "write")

    def test_publisher_checks_draft_visibility_before_remote_writes(self):
        preflight = section(self.jobs, "release-request", 2)
        self.assertNotIn("publisher-preflight", preflight)
        steps = re.findall(r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - name:|\Z)", self.publish)
        self.assertIn("publisher-preflight", steps[1][1])
        self.assertNotIn("publisher-preflight", self.publish[:self.publish.index(steps[1][0])])
        for name in ["Create version tag on the checked source (never force)",
                     "Push exact tested version image when absent", "Stage draft release and verify all uploaded files"]:
            self.assertGreater([step[0] for step in steps].index(name), 1)

    def test_immutable_checkpoint_is_saved_and_verified_before_draft_writes(self):
        steps = dict(re.findall(r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - name:|\Z)", self.publish))
        names = list(steps)
        ordered = ["Require an anonymous digest pull and usable demo",
                   "Restore immutable same-run checkpoint when present",
                   "Finalize manifest with pushed digest", "Verify release signature (when signed)",
                   "Prepare original assets for immutable checkpoint",
                   "Save original assets once (same run and source)",
                   "Verify saved checkpoint before any draft writes",
                   "Stage draft release and verify all uploaded files",
                   "Publish latest only after versioned image and draft validation", "Publish verified draft"]
        self.assertEqual([names.index(name) for name in ordered], sorted(names.index(name) for name in ordered))
        saved = steps[ordered[5]]
        self.assertRegex(saved, r"uses: actions/upload-artifact@[0-9a-f]{40}")
        self.assertIn("name: release-assets-${{ github.run_id }}-${{ github.sha }}", saved)
        for setting in ["path: release-checkpoint/", "retention-days: 90", "overwrite: false", "if-no-files-found: error"]:
            self.assertIn(setting, saved)
        self.assertIn('REQUIRE_CHECKPOINT: "1"', steps[ordered[6]])
        self.assertIn("restore-checkpoint", steps[ordered[1]])
        self.assertNotIn("if:", steps[ordered[1]])
        for name in [ordered[2], *ordered[4:7]]:
            self.assertIn("if: env.RESTORED_CHECKPOINT != '1'", steps[name])

    def test_release_uses_qualified_checker_while_builds_can_override_it(self):
        expression = field(section(self.text, "env", 0), "FRAMEWORK_REF", 2)
        self.assertEqual(evaluate(expression, "workflow_dispatch", "refs/heads/main", "release", "topic"), "v0.2.1")
        self.assertEqual(evaluate(expression, "workflow_dispatch", "refs/heads/main", "build", "topic"), "topic")
        self.assertEqual(evaluate(expression, "push", "refs/tags/v0.3.0.0", "", ""), "v0.2.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
