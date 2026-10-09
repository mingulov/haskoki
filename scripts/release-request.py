#!/usr/bin/env python3
"""Validate a release request and preserve identities across publication retries.

GitHub and registry calls stay at explicit boundaries. Build requests return
before any release lookup or write. Secrets are read from the environment and
are never printed. The workflow supplies the selected commit, not a moving ref.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

IMAGE = "ghcr.io/mingulov/haskoki-demo"
VERSION = r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}"


class Refusal(Exception):
    """A concrete identity or prerequisite check failed."""


def command(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        # Do not echo arbitrary child output: it could contain credentials.
        raise Refusal(f"{args[0]} {args[1]} failed (exit {result.returncode}); inspect the run")
    return result.stdout


def api(endpoint, allow_absent=False, expected=dict):
    result = subprocess.run(["gh", "api", "--include", endpoint],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    raw = result.stdout.decode("utf-8").replace("\r\n", "\n")
    head, sep, body = raw.partition("\n\n")
    status = re.match(r"HTTP/\S+ (\d{3})\b", head)
    if not sep or not status:
        raise Refusal("GitHub API lookup failed without an HTTP response")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise Refusal("GitHub API lookup returned invalid JSON") from exc
    if not isinstance(payload, expected):
        raise Refusal("GitHub API lookup returned an unexpected response shape")
    code = int(status[1])
    if allow_absent and code == 404 and result.returncode == 1 and payload.get("message") == "Not Found":
        return None
    if result.returncode or code != 200:
        raise Refusal(f"GitHub API lookup failed (HTTP {code}); refusing to assume absence")
    return payload


def marker(request):
    return f"<!-- haskoki-release run={request['run_id']} sha={request['sha']} -->"


def lookup_published_release(request):
    """Read-only preflight can reject published releases, not establish draft absence."""
    api(f"repos/{request['repository']}")
    existing = api(f"repos/{request['repository']}/releases/tags/{request['tag']}", allow_absent=True)
    if existing is not None:
        raise Refusal("a public release already exists; it will not be replaced")


def lookup_release(request):
    """Publisher-only discovery; the workflow grants this job contents:write."""
    # Repository permissions bits are not a visibility oracle for installation
    # tokens. Draft visibility follows the publisher's write-scoped contract.
    api(f"repos/{request['repository']}")
    matches = []
    page = 1
    while True:
        entries = api(f"repos/{request['repository']}/releases?per_page=100&page={page}", expected=list)
        if any(not isinstance(entry, dict) for entry in entries):
            raise Refusal("release list returned an unexpected response shape")
        matches.extend(entry for entry in entries if entry.get("tag_name") == request["tag"])
        if len(entries) < 100:
            break
        page += 1
    if len(matches) > 1:
        raise Refusal("multiple releases reference this version tag; refusing ambiguous ownership")
    if not matches:
        return None
    existing = matches[0]
    if existing.get("draft") is not True:
        raise Refusal("a public release already exists; it will not be replaced")
    if not isinstance(existing.get("id"), int) or existing["id"] <= 0:
        raise Refusal("draft release identity is malformed")
    if marker(request) not in (existing.get("body") or ""):
        raise Refusal("existing draft belongs to another run or source; inspect it before recovery")
    return existing


def check_tag(root, tag, sha):
    raw = command("git", "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}", cwd=root)
    refs = dict(line.split()[::-1] for line in raw.decode().splitlines())
    target = refs.get(f"refs/tags/{tag}^{{}}", refs.get(f"refs/tags/{tag}"))
    if target and target != sha:
        raise Refusal("existing version tag points to a different commit; never move it")
    return target is not None


def request_context(root, env):
    event, ref = env.get("GITHUB_EVENT_NAME"), env.get("GITHUB_REF", "")
    mode = env.get("RELEASE_MODE", "build")
    manual = event == "workflow_dispatch" and mode == "release"
    tagged = event == "push" and ref.startswith("refs/tags/v")
    if not manual and not tagged:
        if mode not in ("build", "release"):
            raise Refusal("unknown workflow mode")
        return None
    if manual and ref != "refs/heads/main":
        raise Refusal("manual releases must select main")
    version = env.get("RELEASE_VERSION", "") if manual else ref.removeprefix("refs/tags/v")
    if re.fullmatch(VERSION, version) is None:
        raise Refusal("version must be four decimal components, for example 0.3.0.0")
    source = (root / "haskoki.cabal").read_text()
    match = re.search(r"^version:\s*(\S+)\s*$", source, re.M)
    if not match or match[1] != version:
        raise Refusal("requested version disagrees with haskoki.cabal")
    for rel, pattern, label in [
        ("docker/haskoki-demo", r'^VERSION="([^"\n]+)"$', "entrypoint"),
        ("docker/Dockerfile.demo", r"^ARG VERSION=(\S+)$", "Dockerfile"),
    ]:
        pin = re.search(pattern, (root / rel).read_text(), re.M)
        if not pin or pin[1] != version:
            raise Refusal(f"{label} version disagrees with Cabal; update all release identities")
    notes = f"docs/release-notes-{version}.md"
    if not (root / notes).is_file():
        raise Refusal(f"release notes missing: {notes}")
    sha = env.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Refusal("selected source SHA is malformed")
    if command("git", "rev-parse", "HEAD", cwd=root).decode().strip() != sha:
        raise Refusal("checkout does not match the selected source SHA")
    repository = env.get("GITHUB_REPOSITORY", "")
    if repository != "mingulov/haskoki":
        raise Refusal("publication is configured only for mingulov/haskoki")
    run_id = env.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[0-9]+", run_id):
        raise Refusal("workflow run identity is missing")
    return {"version": version, "tag": f"v{version}", "sha": sha,
            "repository": repository, "run_id": run_id, "manual": manual, "notes": notes}


def preflight(root, env, include_drafts=False):
    request = request_context(root, env)
    if request is None:
        return None
    # Signing is OPTIONAL: an absent HASKOKI_RELEASE_SIGNING_KEY secret
    # releases unsigned (five assets, no SHA256SUMS.asc) instead of
    # refusing. A present signature is always verified (validate_assets).
    check_tag(root, request["tag"], request["sha"])
    if include_drafts:
        lookup_release(request)
    else:
        lookup_published_release(request)
    return request


def ensure_tag(root, request):
    if check_tag(root, request["tag"], request["sha"]):
        return
    if not request["manual"]:
        raise Refusal("owner-pushed release tag disappeared")
    # No force and no moving ref: a competing creator causes push to fail.
    command("git", "-c", "user.name=github-actions[bot]", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "tag", "-a", request["tag"], request["sha"], "-m",
            f"Haskoki {request['version']} demonstrator\n{marker(request)}", cwd=root)
    command("git", "push", "origin", f"refs/tags/{request['tag']}", cwd=root)


def check_labels(request, labels):
    want = {"org.opencontainers.image.version": request["version"],
            "org.opencontainers.image.revision": request["sha"],
            "org.opencontainers.image.source": "https://github.com/mingulov/haskoki"}
    if any(labels.get(k) != v for k, v in want.items()):
        raise Refusal("image source/version labels disagree with the selected release")


def check_image(request, tested_config_id, identity):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", tested_config_id or ""):
        raise Refusal("tested image configuration digest is missing or malformed")
    if identity.get("id") != tested_config_id:
        raise Refusal("versioned image differs from tested bytes or source labels; refusing replacement")
    check_labels(request, identity.get("labels", {}))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity.get("digest", "")):
        raise Refusal("registry image digest is missing or malformed")


def archive_config(archive):
    # Docker save supplies a compatibility manifest.json even with the OCI
    # blobs/sha256 layout. Read members in place; never extract archive paths.
    with tarfile.open(archive, "r:*") as saved:
        member = saved.extractfile("manifest.json")
        manifest = json.load(member) if member else []
        if len(manifest) != 1 or not isinstance(manifest[0].get("Config"), str):
            raise Refusal("saved image must identify exactly one configuration")
        config_member = saved.extractfile(manifest[0]["Config"])
        if config_member is None:
            raise Refusal("saved image configuration is missing")
        raw = config_member.read()
    config = json.loads(raw)
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise Refusal("saved image does not target Linux amd64")
    return "sha256:" + hashlib.sha256(raw).hexdigest(), config


def archive_config_id(archive):
    return archive_config(archive)[0]


def registry_identity(request, env):
    """Authenticated, read-only GHCR lookup. Only typed registry 404s mean absence."""
    credentials = base64.b64encode(f"{env['GITHUB_ACTOR']}:{env['GH_TOKEN']}".encode()).decode()
    scope = urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:mingulov/haskoki-demo:pull,push"})
    token_request = urllib.request.Request(f"https://ghcr.io/token?{scope}",
                                           headers={"Authorization": f"Basic {credentials}"})
    try:
        with urllib.request.urlopen(token_request, timeout=60) as response:
            token = json.load(response)["token"]
    except (urllib.error.URLError, ValueError, KeyError) as exc:
        raise Refusal("GHCR authentication lookup failed; check package permissions") from exc
    accept = ", ".join(["application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json",
                        "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json"])

    def get(path, absent=False):
        req = urllib.request.Request(f"https://ghcr.io/v2/mingulov/haskoki-demo/{path}",
                                     headers={"Authorization": f"Bearer {token}", "Accept": accept})
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                raw = response.read()
                return raw, response.headers.get("Docker-Content-Digest")
        except urllib.error.HTTPError as exc:
            body = exc.read()
            exc.close()
            if absent and exc.code == 404:
                try:
                    errors = json.loads(body).get("errors", [])
                except ValueError:
                    errors = []
                if errors and all(e.get("code") in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN") for e in errors):
                    return None
            raise Refusal(f"GHCR lookup failed (HTTP {exc.code}); refusing to assume absence") from exc
        except urllib.error.URLError as exc:
            raise Refusal("GHCR lookup failed; refusing to assume absence") from exc

    result = get(f"manifests/{request['tag']}", absent=True)
    if result is None:
        return None
    raw, reported_digest = result
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if reported_digest != digest:
        raise Refusal("registry manifest bytes disagree with its digest")
    manifest = json.loads(raw)
    if "manifests" in manifest:
        candidates = [m for m in manifest["manifests"] if m.get("platform", {}).get("os") == "linux"
                      and m.get("platform", {}).get("architecture") == "amd64"]
        if len(candidates) != 1:
            raise Refusal("registry image must identify exactly one Linux amd64 image")
        child = candidates[0]["digest"]
        child_raw, _ = get(f"manifests/{child}")
        if "sha256:" + hashlib.sha256(child_raw).hexdigest() != child:
            raise Refusal("registry child manifest hash mismatch")
        manifest = json.loads(child_raw)
    image_id = manifest["config"]["digest"]
    config_raw, _ = get(f"blobs/{image_id}")
    if "sha256:" + hashlib.sha256(config_raw).hexdigest() != image_id:
        raise Refusal("registry image configuration hash mismatch")
    config = json.loads(config_raw)
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise Refusal("registry image does not target Linux amd64")
    return {"id": image_id, "digest": digest, "labels": config.get("config", {}).get("Labels") or {}}


def required_assets(request):
    """The five assets every release carries, signed or not."""
    version = request["version"]
    return [f"haskoki-{version}-linux-x86_64.tar.gz", f"haskoki-{version}.tar.gz",
            f"test-results-{version}.tar.gz", "release-manifest.json", "SHA256SUMS"]


SIGNATURE = "SHA256SUMS.asc"


def asset_names(request):
    """Canonical six-asset (signed) shape: fixture builders and asset-id mapping."""
    return required_assets(request) + [SIGNATURE]


def present_assets(request, directory):
    """Required five plus the signature exactly when its file is present."""
    names = required_assets(request)
    if (directory / SIGNATURE).is_file():
        names = names + [SIGNATURE]
    return names


def validate_assets(directory, request, digest):
    names = present_assets(request, directory)
    required = required_assets(request)
    if any(not (directory / n).is_file() for n in required):
        raise Refusal("release is missing one of its five required assets")
    checks = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in checks:
            raise Refusal("release checksum file is malformed")
        checks[match[2]] = match[1]
    if set(checks) != set(required[:4]):
        raise Refusal("release checksum set must contain exactly the three archives and manifest")
    for name, expected in checks.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise Refusal(f"release checksum mismatch: {name}")
    manifest = json.loads((directory / "release-manifest.json").read_text())
    if (manifest.get("version") != request["version"] or manifest.get("source", {}).get("sha") != request["sha"]
            or manifest.get("oci_digest") != digest):
        raise Refusal("manifest differs from the selected source, version or image digest")
    if SIGNATURE in names:
        command("gpg", "--batch", "--no-tty", "--verify", str(directory / SIGNATURE),
                str(directory / "SHA256SUMS"))


def checkpoint_name(request):
    return f"release-assets-{request['run_id']}-{request['sha']}"


def find_checkpoint(request):
    matches = []
    page = 1
    while True:
        payload = api(f"repos/{request['repository']}/actions/runs/{request['run_id']}/artifacts?per_page=100&page={page}")
        entries = payload.get("artifacts")
        if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
            raise Refusal("checkpoint artifact list returned an unexpected response shape")
        matches.extend(entry for entry in entries if entry.get("name") == checkpoint_name(request))
        if len(entries) < 100:
            break
        page += 1
    if len(matches) > 1:
        raise Refusal("multiple checkpoint artifacts match; refusing ambiguous identity")
    if not matches:
        return None
    artifact = matches[0]
    if artifact.get("expired") is not False:
        raise Refusal("release checkpoint expired or unavailable; do not replace the draft or artifact")
    run = artifact.get("workflow_run") or {}
    if (str(run.get("id")) != request["run_id"] or run.get("head_sha") != request["sha"]
            or not isinstance(artifact.get("id"), int) or artifact["id"] <= 0):
        raise Refusal("checkpoint artifact run/source identity does not match")
    return artifact


def checkpoint_metadata(request, digest, config_id, directory):
    return {"schema": 1, "run_id": request["run_id"], "sha": request["sha"],
            "tag": request["tag"], "oci_digest": digest, "config_id": config_id,
            "files": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                      for name in present_assets(request, directory)}}


def prepare_checkpoint(directory, checkpoint, request, digest, config_id):
    """Stage the required files (plus the signature when present) and metadata for upload-artifact."""
    names = present_assets(request, directory)
    validate_assets(directory, request, digest)
    if find_checkpoint(request) is not None:
        raise Refusal("checkpoint already exists; restore it instead of replacing its files")
    checkpoint.mkdir()
    for name in names:
        (checkpoint / name).write_bytes((directory / name).read_bytes())
    (checkpoint / "release-checkpoint.json").write_text(json.dumps(
        checkpoint_metadata(request, digest, config_id, checkpoint), indent=2) + "\n")


def restore_checkpoint(directory, request, digest, config_id):
    """Restore original bytes before any draft create/upload, including partial retries."""
    existing = lookup_release(request)
    artifact = find_checkpoint(request)
    if artifact is None:
        if existing is not None:
            raise Refusal("release checkpoint is missing for the existing draft; refusing an unsafe retry")
        return False
    raw = command("gh", "api", f"repos/{request['repository']}/actions/artifacts/{artifact['id']}/zip")
    required = required_assets(request)
    allowed = [set(required) | {"release-checkpoint.json"},
               set(required) | {SIGNATURE, "release-checkpoint.json"}]
    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.namelist()
            if len(members) != len(set(members)) or set(members) not in allowed:
                raise Refusal("checkpoint archive must contain exactly five assets (unsigned) or six (signed), plus its metadata")
            for name in members:
                (stage / name).write_bytes(archive.read(name))
        names = present_assets(request, stage)
        metadata = json.loads((stage / "release-checkpoint.json").read_text())
        if metadata != checkpoint_metadata(request, digest, config_id, stage):
            raise Refusal("checkpoint metadata or file identity does not match")
        validate_assets(stage, request, digest)
        # Check against the independently staged bundle/source inputs of this run.
        for name in required[:2]:
            if hashlib.sha256((stage / name).read_bytes()).digest() != hashlib.sha256((directory / name).read_bytes()).digest():
                raise Refusal("checkpoint bundle/source differs from this run's checked artifacts")
        # Apply only after the complete archive, metadata and signature verify.
        for name in names:
            (directory / name).write_bytes((stage / name).read_bytes())
        # The restored set is the run's immutable record: a signature left
        # over from an unsigned checkpoint's signed retry must not linger.
        stale = directory / SIGNATURE
        if SIGNATURE not in names and (stale.is_file() or stale.is_symlink()):
            stale.unlink()
    return True


def stage_draft(root, directory, request, digest):
    names = present_assets(request, directory)
    validate_assets(directory, request, digest)
    existing = lookup_release(request)
    if existing is None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md") as notes:
            notes.write((root / request["notes"]).read_text() + "\n\n" + marker(request) + "\n")
            notes.flush()
            command("gh", "release", "create", request["tag"], "--repo", request["repository"],
                    "--draft", "--verify-tag", "--title", f"haskoki {request['tag']}", "--notes-file", notes.name)
        existing = lookup_release(request)
        if existing is None:
            raise Refusal("new draft release could not be verified")
    assets = existing.get("assets", [])
    if len({a["name"] for a in assets}) != len(assets) or any(a["name"] not in names for a in assets):
        raise Refusal("draft contains unexpected or duplicate assets")
    for asset in assets:
        remote = command("gh", "api", f"repos/{request['repository']}/releases/assets/{asset['id']}",
                         "-H", "Accept: application/octet-stream")
        if hashlib.sha256(remote).digest() != hashlib.sha256((directory / asset["name"]).read_bytes()).digest():
            raise Refusal(f"draft asset differs from the checkpoint: {asset['name']}; refusing replacement")
    missing = [str(directory / n) for n in names if n not in {a["name"] for a in assets}]
    if missing:
        command("gh", "release", "upload", request["tag"], *missing, "--repo", request["repository"])
    # Verify all downloaded bytes, not merely the successful upload exit code.
    final = lookup_release(request)
    assets = final.get("assets", []) if final else []
    if len(assets) != len(names) or {a["name"] for a in assets} != set(names):
        raise Refusal(f"draft did not receive all {len(names)} assets")
    for asset in assets:
        remote = command("gh", "api", f"repos/{request['repository']}/releases/assets/{asset['id']}",
                         "-H", "Accept: application/octet-stream")
        if hashlib.sha256(remote).digest() != hashlib.sha256((directory / asset["name"]).read_bytes()).digest():
            raise Refusal(f"uploaded draft asset differs: {asset['name']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["archive-config", "preflight", "publisher-preflight", "tag", "registry",
                                              "restore-checkpoint", "prepare-checkpoint", "stage-draft", "publish-draft"])
    parser.add_argument("--assets", type=Path, default=Path("dist-release"))
    parser.add_argument("--checkpoint", type=Path, default=Path("release-checkpoint"))
    parser.add_argument("--image-archive", type=Path, default=Path("demo-image.tar.gz"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    env = os.environ
    try:
        if args.operation == "archive-config":
            config_id, config = archive_config(args.image_archive)
            version = re.search(r"^version:\s*(\S+)", (root / "haskoki.cabal").read_text(), re.M)[1]
            check_labels({"version": version, "sha": env["GITHUB_SHA"]}, config.get("config", {}).get("Labels") or {})
            with open(env["GITHUB_OUTPUT"], "a") as out:
                out.write(f"configid={config_id}\n")
            print(f"tested archive configuration digest: {config_id}")
            return
        request = (preflight(root, env, include_drafts=args.operation == "publisher-preflight")
                   if args.operation in ("preflight", "publisher-preflight") else request_context(root, env))
        if request is None:
            print("build mode: no release actions")
            return
        if args.operation in ("preflight", "publisher-preflight"):
            if env.get("GITHUB_OUTPUT"):
                with open(env["GITHUB_OUTPUT"], "a") as out:
                    out.write(f"tag={request['tag']}\nversion={request['version']}\n")
            print(f"release request validated: {request['tag']} at {request['sha']}")
            if args.operation == "preflight":
                print("published-release preflight only; draft discovery runs in the write-scoped publisher")
        elif args.operation == "tag":
            lookup_release(request)
            ensure_tag(root, request)
        elif args.operation == "registry":
            identity = registry_identity(request, env)
            if identity is None:
                if env.get("REQUIRE_IMAGE") == "1":
                    raise Refusal("versioned image is missing after push")
                print("versioned image does not exist yet")
            else:
                check_image(request, env.get("TESTED_CONFIG_ID"), identity)
                if env.get("GITHUB_ENV"):
                    with open(env["GITHUB_ENV"], "a") as out:
                        out.write(f"PUSHED_DIGEST={IMAGE}@{identity['digest']}\nPUSHED_DIGEST_ONLY={identity['digest']}\nVERSION_IMAGE_EXISTS=1\n")
                print(f"verified versioned image: {IMAGE}@{identity['digest']}")
        elif args.operation == "restore-checkpoint":
            if restore_checkpoint(args.assets, request, env["PUSHED_DIGEST"], env["TESTED_CONFIG_ID"]):
                with open(env["GITHUB_ENV"], "a") as out:
                    out.write("RESTORED_CHECKPOINT=1\n")
                print(f"restored immutable checkpoint: {checkpoint_name(request)}")
            elif env.get("REQUIRE_CHECKPOINT") == "1":
                raise Refusal("release checkpoint is missing after upload; refusing any draft writes")
        elif args.operation == "prepare-checkpoint":
            prepare_checkpoint(args.assets, args.checkpoint, request, env["PUSHED_DIGEST"], env["TESTED_CONFIG_ID"])
            print(f"checkpoint ready for upload: {checkpoint_name(request)}")
        elif args.operation == "stage-draft":
            stage_draft(root, args.assets, request, env["PUSHED_DIGEST"])
        elif args.operation == "publish-draft":
            # Recheck owned draft files immediately before making it public.
            stage_draft(root, args.assets, request, env["PUSHED_DIGEST"])
            command("gh", "release", "edit", request["tag"], "--repo", request["repository"], "--draft=false")
    except (Refusal, OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print(f"release refused: {exc}")
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
