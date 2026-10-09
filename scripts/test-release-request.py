#!/usr/bin/env python3
"""Release behavior tests: real temporary Git repositories, fake API boundaries."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.parse
import warnings
import zipfile
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("release-request.py")
spec = importlib.util.spec_from_file_location("release_request", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "source"
        self.remote = Path(self.temp.name) / "origin.git"
        self.root.mkdir()
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "config", "user.email", "release-test@example.invalid")
        git(self.root, "config", "user.name", "Release test")
        for name, text in {
            "haskoki.cabal": "version: 0.3.0.0\n",
            "client/haskoki-client.cabal": "version: 0.1.0.0\n",
            "docker/haskoki-demo": 'VERSION="0.3.0.0"\n',
            "docker/Dockerfile.demo": "ARG VERSION=0.3.0.0\n",
            "docs/release-notes-0.3.0.0.md": "# Demonstrator release\n",
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "Fixture")
        git(self.root, "init", "-q", "--bare", str(self.remote))
        git(self.root, "remote", "add", "origin", str(self.remote))
        git(self.root, "push", "-q", "origin", "main")
        self.env = {
            "RELEASE_MODE": "release", "RELEASE_VERSION": "0.3.0.0",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": git(self.root, "rev-parse", "HEAD"),
            "GITHUB_REPOSITORY": "mingulov/haskoki", "GITHUB_RUN_ID": "1234",
            "HASKOKI_RELEASE_SIGNING_KEY": "private-key-fixture",
        }
        self.api = patch.object(release, "api", return_value=None)
        self.api_mock = self.api.start()

    def tearDown(self):
        self.api.stop()
        self.temp.cleanup()

    def request(self, **changes):
        return release.preflight(self.root, self.env | changes)

    def test_main_request_pins_selected_sha_without_writes(self):
        result = self.request()
        self.assertEqual(result["tag"], "v0.3.0.0")
        self.assertEqual(result["sha"], self.env["GITHUB_SHA"])
        self.assertEqual(git(self.root, "ls-remote", "origin", "refs/tags/*"), "")

    def test_build_mode_has_no_release_calls_or_writes(self):
        result = self.request(RELEASE_MODE="build", GITHUB_REF="refs/heads/topic",
                              RELEASE_VERSION="", HASKOKI_RELEASE_SIGNING_KEY="")
        self.assertIsNone(result)
        self.api_mock.assert_not_called()
        self.assertEqual(git(self.root, "ls-remote", "origin", "refs/tags/*"), "")

    def test_non_main_release_is_rejected(self):
        with self.assertRaisesRegex(release.Refusal, "main"):
            self.request(GITHUB_REF="refs/heads/topic")
        self.api_mock.assert_not_called()

    def test_malformed_and_mismatched_versions_are_rejected(self):
        for version in ["", "0.3.0", "v0.3.0.0", "0.3.0.0\n", "01.3.0.0",
                        "0.3.0.0;touch /tmp/no", "0.4.0.0"]:
            with self.subTest(version=version), self.assertRaises(release.Refusal):
                self.request(RELEASE_VERSION=version)

    def test_missing_signing_input_is_rejected(self):
        with self.assertRaisesRegex(release.Refusal, "SIGNING_KEY"):
            self.request(HASKOKI_RELEASE_SIGNING_KEY="")

    def test_checkout_must_equal_selected_sha(self):
        with self.assertRaisesRegex(release.Refusal, "checkout"):
            self.request(GITHUB_SHA="a" * 40)

    def test_version_drift_in_entrypoint_is_rejected(self):
        (self.root / "docker/haskoki-demo").write_text('VERSION="0.2.0.0"\n')
        with self.assertRaisesRegex(release.Refusal, "entrypoint"):
            self.request()

    def test_existing_tag_on_other_sha_is_rejected(self):
        git(self.root, "tag", "v0.3.0.0")
        git(self.root, "push", "-q", "origin", "v0.3.0.0")
        (self.root / "new").write_text("changed\n")
        git(self.root, "add", "new")
        git(self.root, "commit", "-qm", "Second fixture")
        with self.assertRaisesRegex(release.Refusal, "different commit"):
            self.request(GITHUB_SHA=git(self.root, "rev-parse", "HEAD"))

    def test_exact_sha_tag_retry_is_accepted(self):
        git(self.root, "tag", "-a", "v0.3.0.0", "-m", "Fixture tag")
        git(self.root, "push", "-q", "origin", "v0.3.0.0")
        self.assertEqual(self.request()["tag"], "v0.3.0.0")

    def test_tag_creation_pins_source_and_retry_does_not_move_it(self):
        request = self.request()
        release.ensure_tag(self.root, request)
        refs = git(self.root, "ls-remote", "origin", "refs/tags/v0.3.0.0", "refs/tags/v0.3.0.0^{}")
        self.assertIn(request["sha"] + "\trefs/tags/v0.3.0.0^{}", refs)
        self.assertIn(release.marker(request), git(self.root, "tag", "-l", "v0.3.0.0", "--format=%(contents)"))
        release.ensure_tag(self.root, request)
        self.assertEqual(git(self.root, "ls-remote", "origin", "refs/tags/v0.3.0.0", "refs/tags/v0.3.0.0^{}"), refs)

    def test_readonly_preflight_rejects_a_published_release(self):
        self.api_mock.return_value = {"draft": False, "body": ""}
        with self.assertRaisesRegex(release.Refusal, "public release"):
            self.request()

    def test_readonly_preflight_defers_draft_discovery_to_publisher(self):
        self.assertEqual(self.request()["sha"], self.env["GITHUB_SHA"])
        self.assertTrue(all("/releases?" not in call.args[0] for call in self.api_mock.call_args_list))

    def test_failed_api_lookup_is_not_absence(self):
        self.api_mock.side_effect = release.Refusal("API lookup failed")
        with self.assertRaisesRegex(release.Refusal, "API lookup failed"):
            self.request()

    def test_owner_pushed_tag_route_is_retained(self):
        git(self.root, "tag", "v0.3.0.0")
        git(self.root, "push", "-q", "origin", "v0.3.0.0")
        self.assertEqual(self.request(GITHUB_EVENT_NAME="push",
                                     GITHUB_REF="refs/tags/v0.3.0.0",
                                     RELEASE_MODE="build")["tag"], "v0.3.0.0")


class BoundaryTests(unittest.TestCase):
    def test_saved_configuration_digest_is_independent_of_containerd_manifest_id(self):
        config = b'{"os":"linux","architecture":"amd64","rootfs":{"diff_ids":["sha256:fixture"]},"config":{"Labels":{}}}'
        expected = "sha256:" + hashlib.sha256(config).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "image.tar.gz"
            with tarfile.open(archive, "w:gz") as out:
                for name, content in [("manifest.json", b'[{"Config":"blobs/sha256/config","RepoTags":["haskoki-demo:0.3.0.0"]}]'),
                                      ("blobs/sha256/config", config)]:
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    out.addfile(member, io.BytesIO(content))
            self.assertEqual(release.archive_config_id(archive), expected)
            # .Id can be an OCI manifest digest on containerd. The actual
            # saved config digest, covering labels and DiffIDs, is the oracle.
            containerd_id = "sha256:" + "d" * 64
            self.assertNotEqual(expected, containerd_id)

    def test_registry_absence_is_typed_and_access_denial_fails_closed(self):
        class Response:
            headers = {}

            def __enter__(self):
                return io.BytesIO(b'{"token":"fixture-token"}')

            def __exit__(self, *args):
                pass

        for status, code, absent in [(404, "MANIFEST_UNKNOWN", True),
                                     (404, "NAME_UNKNOWN", True),
                                     (404, "DENIED", False), (403, "DENIED", False)]:
            error = urllib.error.HTTPError("https://ghcr.io/fixture", status, "fixture", {},
                io.BytesIO(json.dumps({"errors": [{"code": code}]}).encode()))
            with self.subTest(status=status, code=code), patch.object(release.urllib.request, "urlopen",
                    side_effect=[Response(), error]):
                req = {"tag": "v0.3.0.0"}
                env = {"GITHUB_ACTOR": "fixture", "GH_TOKEN": "fixture"}
                if absent:
                    self.assertIsNone(release.registry_identity(req, env))
                else:
                    with self.assertRaises(release.Refusal):
                        release.registry_identity(req, env)

    def test_registry_bytes_are_verified_before_image_identity_is_trusted(self):
        config = json.dumps({"os": "linux", "architecture": "amd64", "config": {"Labels": {}}}).encode()
        image_id = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = json.dumps({"config": {"digest": image_id}}).encode()
        digest = "sha256:" + hashlib.sha256(manifest).hexdigest()

        class Response:
            def __init__(self, raw, content_digest=None):
                self.raw = raw
                self.headers = {"Docker-Content-Digest": content_digest}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self):
                return self.raw

        for raw_config, success in [(config, True), (b"tampered", False)]:
            with self.subTest(success=success), patch.object(release.urllib.request, "urlopen", side_effect=[
                    Response(b'{"token":"fixture"}'), Response(manifest, digest), Response(raw_config)]):
                if success:
                    result = release.registry_identity({"tag": "v0.3.0.0"},
                        {"GITHUB_ACTOR": "fixture", "GH_TOKEN": "fixture"})
                    self.assertEqual(result["id"], image_id)
                    self.assertEqual(result["digest"], digest)
                else:
                    with self.assertRaisesRegex(release.Refusal, "hash mismatch"):
                        release.registry_identity({"tag": "v0.3.0.0"},
                            {"GITHUB_ACTOR": "fixture", "GH_TOKEN": "fixture"})

    def test_only_explicit_http_404_can_mean_absence(self):
        for rc, raw, absent in [
            (1, 'HTTP/2.0 404 Not Found\n\n{"message":"Not Found"}', True),
            (1, 'HTTP/2.0 403 Forbidden\n\n{"message":"Forbidden"}', False),
            (1, "connection refused", False),
            (0, 'HTTP/2.0 200 OK\n\n{"draft":false}', False),
        ]:
            with self.subTest(raw=raw), patch.object(release.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], rc, raw.encode(), b"")
                if absent:
                    self.assertIsNone(release.api("repos/mingulov/haskoki/releases/tags/v0.3.0.0",
                                                  allow_absent=True))
                elif rc:
                    with self.assertRaises(release.Refusal):
                        release.api("repos/mingulov/haskoki/releases/tags/v0.3.0.0", allow_absent=True)
                else:
                    self.assertEqual(release.api("fixture"), {"draft": False})

    def test_existing_registry_image_must_match_config_and_labels(self):
        req = {"version": "0.3.0.0", "sha": "a" * 40}
        expected = "sha256:" + "b" * 64
        valid = {"id": expected, "digest": "sha256:" + "c" * 64,
                 "labels": {"org.opencontainers.image.version": "0.3.0.0",
                            "org.opencontainers.image.revision": "a" * 40,
                            "org.opencontainers.image.source": "https://github.com/mingulov/haskoki"}}
        release.check_image(req, expected, valid)
        for key, changed in [("id", "sha256:" + "d" * 64), ("labels", {})]:
            with self.subTest(key=key), self.assertRaises(release.Refusal):
                release.check_image(req, expected, valid | {key: changed})

    def test_signed_asset_checksum_set_is_exact_and_manifest_identity_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            req = {"version": "0.3.0.0", "sha": "a" * 40}
            digest = "ghcr.io/mingulov/haskoki-demo@sha256:" + "b" * 64
            for name in release.asset_names(req):
                (root / name).write_bytes(b"fixture")
            (root / "release-manifest.json").write_text(json.dumps({
                "version": "0.3.0.0", "source": {"sha": "a" * 40}, "oci_digest": digest}))
            names = release.asset_names(req)[:4]
            (root / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256((root / n).read_bytes()).hexdigest()}  {n}\n" for n in names))
            with patch.object(release, "command"):
                release.validate_assets(root, req, digest)
                (root / names[0]).write_bytes(b"tampered")
                with self.assertRaisesRegex(release.Refusal, "checksum"):
                    release.validate_assets(root, req, digest)


class DraftTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.req = {"version": "0.3.0.0", "tag": "v0.3.0.0", "sha": "a" * 40,
                    "repository": "mingulov/haskoki", "run_id": "1234", "notes": "notes.md"}
        (self.root / "notes.md").write_text("Release notes\n")
        self.digest = "ghcr.io/mingulov/haskoki-demo@sha256:" + "b" * 64
        for name in release.asset_names(self.req):
            (self.root / name).write_bytes(b"fixture")
        (self.root / "release-manifest.json").write_text(json.dumps({
            "version": "0.3.0.0", "source": {"sha": "a" * 40}, "oci_digest": self.digest}))
        (self.root / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.root / name).read_bytes()).hexdigest()}  {name}\n"
            for name in release.asset_names(self.req)[:4]))
        self.remote = {name: (self.root / name).read_bytes() for name in release.asset_names(self.req)}
        self.uploads = []

    def tearDown(self):
        self.temp.cleanup()

    def lookup(self, request):
        return {"draft": True, "body": release.marker(request),
                "assets": [{"id": name, "name": name} for name in self.remote]}

    def boundary(self, *args, **kwargs):
        if args[:2] == ("gh", "api"):
            return self.remote[args[2].split("/")[-1]]
        if args[:3] == ("gh", "release", "upload"):
            for path in args[4:args.index("--repo")]:
                asset = Path(path)
                self.remote[asset.name] = asset.read_bytes()
                self.uploads.append(asset.name)
            return b""
        if args[0] == "gpg":
            return b""
        raise AssertionError(f"unexpected write: {args[:3]}")

    def test_identical_complete_draft_retry_has_no_uploads(self):
        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", self.boundary):
            release.stage_draft(self.root, self.root, self.req, self.digest)
        self.assertEqual(self.uploads, [])

    def test_partial_owned_draft_uploads_only_missing_bytes(self):
        del self.remote["SHA256SUMS.asc"]
        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", self.boundary):
            release.stage_draft(self.root, self.root, self.req, self.digest)
        self.assertEqual(self.uploads, ["SHA256SUMS.asc"])

    def test_partial_draft_with_changed_asset_refuses_without_upload(self):
        self.remote["SHA256SUMS.asc"] = b"foreign bytes"
        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", self.boundary):
            with self.assertRaisesRegex(release.Refusal, "draft asset differs"):
                release.stage_draft(self.root, self.root, self.req, self.digest)
        self.assertEqual(self.uploads, [])

    def test_signature_failure_blocks_any_draft_upload(self):
        def failed_signature(*args, **kwargs):
            if args[0] == "gpg":
                raise release.Refusal("signature failed")
            return self.boundary(*args, **kwargs)

        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", failed_signature):
            with self.assertRaisesRegex(release.Refusal, "signature failed"):
                release.stage_draft(self.root, self.root, self.req, self.digest)
        self.assertEqual(self.uploads, [])


class ApiLifecycleTests(unittest.TestCase):
    """Model published-only tag lookup at the real gh subprocess boundary."""

    def setUp(self):
        DraftTests.setUp(self)
        self.remote.clear()
        self.current = None
        self.calls = []
        self.fail_upload_after = None
        self.artifacts = []
        self.checkpoint_zip = b""
        self.config_id = "sha256:" + "d" * 64

    def tearDown(self):
        DraftTests.tearDown(self)

    def response(self, args, status, payload):
        raw = json.dumps(payload).encode()
        if "--include" in args:
            raw = f"HTTP/2.0 {status} fixture\n\n".encode() + raw
        return subprocess.CompletedProcess(args, 0 if status == 200 else 1, raw, b"")

    def transport(self, args, **kwargs):
        args = list(args)
        self.calls.append(args)
        if args[0] == "gpg":
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if args[:2] == ["gh", "api"]:
            endpoint = args[3] if "--include" in args else args[2]
            path, _, query = endpoint.partition("?")
            if path == "repos/mingulov/haskoki":
                return self.response(args, 200, {"permissions": {"push": getattr(self, "push_visibility", True)}})
            if "/releases/tags/" in path:
                # The tag endpoint deliberately cannot discover drafts.
                if self.current and not self.current["draft"]:
                    return self.response(args, 200, self.current)
                return self.response(args, 404, {"message": "Not Found"})
            if path.endswith("/releases"):
                page = int(urllib.parse.parse_qs(query)["page"][0])
                entries = self.release_pages.get(page, []) if hasattr(self, "release_pages") else ([self.current] if self.current else [])
                return self.response(args, 200, entries)
            if "/releases/assets/" in path:
                asset_id = int(path.rsplit("/", 1)[1])
                name = release.asset_names(self.req)[asset_id - 1]
                return subprocess.CompletedProcess(args, 0, self.remote[name], b"")
            if "/actions/runs/" in path and path.endswith("/artifacts"):
                page = int(urllib.parse.parse_qs(query)["page"][0])
                entries = self.artifact_pages.get(page, []) if hasattr(self, "artifact_pages") else self.artifacts
                return self.response(args, 200, {"artifacts": entries})
            if path.endswith("/actions/artifacts/77/zip"):
                return subprocess.CompletedProcess(args, 0, self.checkpoint_zip, b"")
            raise AssertionError(f"unexpected endpoint: {endpoint}")
        if args[:3] == ["gh", "release", "create"]:
            self.assertIsNone(self.current, "must discover an existing draft before writing")
            notes = Path(args[args.index("--notes-file") + 1]).read_text()
            self.current = {"id": 10, "tag_name": self.req["tag"], "draft": True,
                            "body": notes, "assets": []}
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if args[:3] == ["gh", "release", "upload"]:
            for number, path in enumerate(args[4:args.index("--repo")]):
                if self.fail_upload_after is not None and number == self.fail_upload_after:
                    self.fail_upload_after = None
                    return subprocess.CompletedProcess(args, 1, b"", b"injected transient upload failure")
                asset = Path(path)
                self.assertNotIn(asset.name, self.remote, "existing bytes must never be replaced")
                self.remote[asset.name] = asset.read_bytes()
                self.current["assets"].append({"id": release.asset_names(self.req).index(asset.name) + 1,
                                               "name": asset.name})
            return subprocess.CompletedProcess(args, 0, b"", b"")
        raise AssertionError(f"unexpected command: {args[:3]}")

    def save_checkpoint_boundary(self, directory):
        # Model upload-artifact after the real helper stages the seven files.
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for path in directory.iterdir():
                archive.writestr(path.name, path.read_bytes())
        self.checkpoint_zip = stream.getvalue()
        self.artifacts = [{"id": 77, "name": release.checkpoint_name(self.req), "expired": False,
                           "workflow_run": {"id": 1234, "head_sha": self.req["sha"]}}]

    def test_draft_create_discover_upload_rediscover_at_api_boundary(self):
        with patch.object(release.subprocess, "run", self.transport):
            release.stage_draft(self.root, self.root, self.req, self.digest)
            result = release.lookup_release(self.req)
        self.assertEqual(result["id"], 10)
        self.assertEqual(set(self.remote), set(release.asset_names(self.req)))
        self.assertEqual(len([call for call in self.calls if call[:3] == ["gh", "release", "create"]]), 1)

    def test_owned_and_foreign_drafts_found_when_published_tag_is_absent(self):
        self.current = {"id": 10, "tag_name": self.req["tag"], "draft": True,
                        "body": release.marker(self.req), "assets": []}
        with patch.object(release.subprocess, "run", self.transport):
            self.assertEqual(release.lookup_release(self.req)["id"], 10)
            self.current["body"] = "foreign draft"
            with self.assertRaisesRegex(release.Refusal, "another run"):
                release.lookup_release(self.req)
        self.assertFalse(any(call[:3] == ["gh", "release", "create"] for call in self.calls))

    def test_publisher_discovery_does_not_use_repository_permission_bits(self):
        self.push_visibility = False
        with patch.object(release.subprocess, "run", self.transport):
            self.assertIsNone(release.lookup_release(self.req))
        self.assertTrue(any("/releases?" in call[-1] for call in self.calls))

    def test_draft_api_errors_fail_closed_before_any_writes(self):
        def failed_list(args, **kwargs):
            if "/releases?" in args[-1]:
                return self.response(args, 403, {"message": "Forbidden"})
            return self.transport(args, **kwargs)

        with patch.object(release.subprocess, "run", failed_list):
            with self.assertRaises(release.Refusal):
                release.stage_draft(self.root, self.root, self.req, self.digest)
        self.assertIsNone(self.current)
        self.assertEqual(self.remote, {})

    def test_release_discovery_paginates_and_rejects_duplicate_tag(self):
        self.release_pages = {1: [{"tag_name": f"other-{n}"} for n in range(100)],
                              2: [{"id": 10, "tag_name": self.req["tag"], "draft": True,
                                   "body": release.marker(self.req), "assets": []}]}
        with patch.object(release.subprocess, "run", self.transport):
            self.assertEqual(release.lookup_release(self.req)["id"], 10)
            self.release_pages[1][0] = self.release_pages[2][0]
            with self.assertRaisesRegex(release.Refusal, "multiple"):
                release.lookup_release(self.req)

    def test_partial_upload_retries_from_checkpoint_in_fresh_timestamp_changed_directory(self):
        checkpoint = self.root / "checkpoint"
        with patch.object(release.subprocess, "run", self.transport):
            release.prepare_checkpoint(self.root, checkpoint, self.req, self.digest, self.config_id)
            self.save_checkpoint_boundary(checkpoint)
            self.fail_upload_after = 5
            with self.assertRaises(release.Refusal):
                release.stage_draft(self.root, self.root, self.req, self.digest)
            original_remote = dict(self.remote)
            self.assertEqual(len(original_remote), 5)
            retry = self.root / "fresh-retry"
            retry.mkdir()
            for name in release.asset_names(self.req):
                (retry / name).write_bytes((self.root / name).read_bytes())
            manifest = json.loads((retry / "release-manifest.json").read_text())
            manifest["built_utc"] = "a regenerated timestamp"
            (retry / "release-manifest.json").write_text(json.dumps(manifest))
            (retry / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256((retry / name).read_bytes()).hexdigest()}  {name}\n"
                for name in release.asset_names(self.req)[:4]))
            (retry / "SHA256SUMS.asc").write_bytes(b"a regenerated signature")
            release.validate_assets(retry, self.req, self.digest)
            self.assertTrue(release.restore_checkpoint(retry, self.req, self.digest, self.config_id))
            release.stage_draft(self.root, retry, self.req, self.digest)
        self.assertEqual(self.remote["SHA256SUMS.asc"], b"fixture")
        self.assertEqual(self.remote["release-manifest.json"], (self.root / "release-manifest.json").read_bytes())
        self.assertTrue(all(self.remote[name] == value for name, value in original_remote.items()))

    def test_owned_draft_requires_unexpired_same_run_checkpoint(self):
        self.current = {"id": 10, "tag_name": self.req["tag"], "draft": True,
                        "body": release.marker(self.req), "assets": []}
        with patch.object(release.subprocess, "run", self.transport):
            with self.assertRaisesRegex(release.Refusal, "checkpoint.*missing"):
                release.restore_checkpoint(self.root, self.req, self.digest, self.config_id)
            checkpoint = self.root / "checkpoint"
            release.prepare_checkpoint(self.root, checkpoint, self.req, self.digest, self.config_id)
            self.save_checkpoint_boundary(checkpoint)
            self.artifacts[0]["expired"] = True
            with self.assertRaisesRegex(release.Refusal, "expired"):
                release.restore_checkpoint(self.root, self.req, self.digest, self.config_id)
            self.artifacts[0]["expired"] = False
            self.artifacts[0]["workflow_run"]["head_sha"] = "e" * 40
            with self.assertRaisesRegex(release.Refusal, "identity"):
                release.restore_checkpoint(self.root, self.req, self.digest, self.config_id)

    def test_checkpoint_selection_paginates_and_never_replaces_an_existing_artifact(self):
        checkpoint = self.root / "checkpoint"
        with patch.object(release.subprocess, "run", self.transport):
            release.prepare_checkpoint(self.root, checkpoint, self.req, self.digest, self.config_id)
            self.save_checkpoint_boundary(checkpoint)
            self.artifact_pages = {1: [{"name": f"other-{n}"} for n in range(100)], 2: self.artifacts}
            self.assertEqual(release.find_checkpoint(self.req)["id"], 77)
            with self.assertRaisesRegex(release.Refusal, "already exists"):
                release.prepare_checkpoint(self.root, self.root / "replacement", self.req, self.digest, self.config_id)
            self.assertFalse((self.root / "replacement").exists())
            self.artifact_pages[1][0] = self.artifacts[0]
            with self.assertRaisesRegex(release.Refusal, "multiple"):
                release.find_checkpoint(self.req)

    def test_checkpoint_invalid_members_metadata_and_signature_do_not_apply_files(self):
        checkpoint = self.root / "checkpoint"
        with patch.object(release.subprocess, "run", self.transport):
            release.prepare_checkpoint(self.root, checkpoint, self.req, self.digest, self.config_id)
            self.save_checkpoint_boundary(checkpoint)
        original_zip = self.checkpoint_zip
        original_files = {name: (self.root / name).read_bytes() for name in release.asset_names(self.req)}
        for mutation in ["extra", "path", "duplicate", "metadata", "hash", "signature"]:
            with self.subTest(mutation=mutation):
                stream = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(original_zip)) as source, zipfile.ZipFile(stream, "w") as target:
                    for name in source.namelist():
                        content = source.read(name)
                        if name == "release-checkpoint.json" and mutation in ("metadata", "hash"):
                            metadata = json.loads(content)
                            if mutation == "metadata":
                                metadata["config_id"] = "sha256:" + "e" * 64
                            else:
                                metadata["files"]["SHA256SUMS.asc"] = "e" * 64
                            content = json.dumps(metadata).encode()
                        member = "../SHA256SUMS.asc" if name == "SHA256SUMS.asc" and mutation == "path" else name
                        target.writestr(member, content)
                    if mutation == "extra":
                        target.writestr("extra", b"unexpected")
                    if mutation == "duplicate":
                        # Duplicate member names are invalid even with identical bytes.
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", UserWarning)
                            target.writestr("SHA256SUMS.asc", b"fixture")
                self.checkpoint_zip = stream.getvalue()

                def boundary(args, **kwargs):
                    if mutation == "signature" and args[0] == "gpg":
                        return subprocess.CompletedProcess(args, 1, b"", b"invalid signature")
                    return self.transport(args, **kwargs)

                with patch.object(release.subprocess, "run", boundary), self.assertRaises(release.Refusal):
                    release.restore_checkpoint(self.root, self.req, self.digest, self.config_id)
                self.assertEqual({name: (self.root / name).read_bytes() for name in original_files}, original_files)
                self.assertFalse((self.root / "release-checkpoint.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
