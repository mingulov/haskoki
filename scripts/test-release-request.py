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

    def test_public_release_and_foreign_draft_are_rejected(self):
        for existing in [{"draft": False, "body": ""},
                         {"draft": True, "body": "foreign draft"}]:
            self.api_mock.return_value = existing
            with self.subTest(existing=existing), self.assertRaises(release.Refusal):
                self.request()

    def test_owned_draft_retry_is_accepted(self):
        request = self.request()
        self.api_mock.return_value = {"draft": True, "body": release.marker(request)}
        self.assertEqual(self.request()["sha"], self.env["GITHUB_SHA"])

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

    def test_complete_owned_draft_restores_original_signed_files(self):
        (self.root / "SHA256SUMS.asc").write_bytes(b"a regenerated signature")
        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", self.boundary):
            self.assertTrue(release.restore_draft(self.root, self.req, self.digest))
        self.assertEqual((self.root / "SHA256SUMS.asc").read_bytes(), b"fixture")
        self.assertEqual(self.uploads, [])

    def test_complete_draft_with_wrong_source_is_not_restored(self):
        changed = json.loads(self.remote["release-manifest.json"])
        changed["source"]["sha"] = "c" * 40
        self.remote["release-manifest.json"] = json.dumps(changed).encode()
        self.remote["SHA256SUMS"] = "".join(
            f"{hashlib.sha256(self.remote[name]).hexdigest()}  {name}\n"
            for name in release.asset_names(self.req)[:4]).encode()
        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", self.boundary):
            with self.assertRaisesRegex(release.Refusal, "signed manifest differs"):
                release.restore_draft(self.root, self.req, self.digest)

    def test_signature_failure_blocks_any_draft_upload(self):
        def failed_signature(*args, **kwargs):
            if args[0] == "gpg":
                raise release.Refusal("signature failed")
            return self.boundary(*args, **kwargs)

        with patch.object(release, "lookup_release", self.lookup), patch.object(release, "command", failed_signature):
            with self.assertRaisesRegex(release.Refusal, "signature failed"):
                release.stage_draft(self.root, self.root, self.req, self.digest)
        self.assertEqual(self.uploads, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
