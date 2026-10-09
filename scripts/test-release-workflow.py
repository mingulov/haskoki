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

    def test_only_publication_job_has_write_permissions(self):
        self.assertEqual(field(section(self.text, "permissions", 0), "contents", 2), "read")
        for job in re.findall(r"(?m)^  ([a-z][a-z0-9-]*):", self.jobs):
            if job != "publish":
                self.assertNotRegex(section(self.jobs, job, 2), r"(?m)^\s+[a-z-]+: write$", "write outside publication")
        permissions = section(self.publish, "permissions", 4)
        for name in ["contents", "packages", "attestations", "id-token"]:
            self.assertEqual(field(permissions, name, 6), "write")

    def test_release_uses_qualified_checker_while_builds_can_override_it(self):
        expression = field(section(self.text, "env", 0), "FRAMEWORK_REF", 2)
        self.assertEqual(evaluate(expression, "workflow_dispatch", "refs/heads/main", "release", "topic"), "v0.2.1")
        self.assertEqual(evaluate(expression, "workflow_dispatch", "refs/heads/main", "build", "topic"), "topic")
        self.assertEqual(evaluate(expression, "push", "refs/tags/v0.3.0.0", "", ""), "v0.2.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
