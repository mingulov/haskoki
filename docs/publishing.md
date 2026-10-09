# Publishing the first demo

The project can be tried from source now. A Docker-only, pull-and-run
announcement needs the publication steps below. This checklist describes
the existing [CI workflow](../.github/workflows/ci.yml); it does not mean
a release has already been published.

## Current position

Checked on 2026-10-09 at `0603322e33b0595a29c89622f49fcb5a5def1a07`:

- [CI](https://github.com/mingulov/haskoki/actions/runs/37774745195)
  completed, including bundle, source-package, and demo-image jobs.
  The publish job was skipped, as expected for a main-branch push.
- [HPC](https://github.com/mingulov/haskoki/actions/runs/37774745165)
  and [nightly properties](https://github.com/mingulov/haskoki/actions/runs/37913805765)
  completed. These do not validate publication.
- GitHub listed no release tags or releases. An anonymous GHCR manifest
  request for `ghcr.io/mingulov/haskoki-demo:v0.3.0.0` was denied.
- The repository listed no Actions secrets. The required release signing
  key is an outstanding owner setup step.

New edits need their own CI run before tagging. An older successful run
does not validate a later revision.

## Before creating the tag

1. Review and integrate the public documentation changes. Select the exact
   release commit and require CI on it, including the demo-image job.
2. Configure the repository secret `HASKOKI_RELEASE_SIGNING_KEY`. The
   workflow imports this exported GPG private key into a temporary keyring;
   the current signing path must work unattended. Keep the private key out
   of the repository and logs.
3. Publish the corresponding public verification key and full fingerprint
   at an owner-controlled location. Add that location to the release notes
   before publishing; a checksum alone does not authenticate a download.
4. Confirm Actions can write repository releases, GHCR packages, and
   attestations. The workflow requests these permissions explicitly.
   Confirm the resulting GHCR package is public.

For a local repeat of all demo-image checks, first build the toolchain
image with the UID/GID arguments in the [README](../README.md). Then use
a disposable evidence directory and an absolute path (the driver also
tests arbitrary UIDs):

```sh
HASKOKI_DEMO_TEST_OUT="$PWD/out/qualification" \
  HASKOKI_DEMO_REVISION="$(git rev-parse HEAD)" \
  sh scripts/test-demo-image.sh
```

This stages the bundle and runs demo, smoke/full checks in both modes,
comparison, examples, and error cases. Allow roughly an hour or more.
The fast and vector CI checker lanes allow reported findings; a passing
job is not a claim of zero findings. The vector lane does not gate publish.
The complete native C driver manifest is a separate `scripts/run-gates.sh`
route with the toolchain and qualified proxy prerequisites; the CI C job
runs a smaller deterministic subset.

## Publish the selected commit

Creating and pushing the tag is the release owner's publication action.
On the approved clean checkout, the commands are:

```sh
git status --short
git rev-parse HEAD
git tag -a v0.3.0.0 -m 'Haskoki 0.3.0.0 demonstrator'
git push origin refs/tags/v0.3.0.0
```

The tag must match the Cabal version exactly: `v0.3.0.0`, not `v0.3.0`.
The tag workflow runs its required jobs, loads the tested image bytes,
pushes the versioned image and `latest`, records the registry digest,
signs checksums, creates attestations, and creates the GitHub release.

Expect these six assets:

| Asset | Purpose |
| --- | --- |
| `haskoki-0.3.0.0-linux-x86_64.tar.gz` | Native module, control tool, runtime libraries, licenses, smoke consumer |
| `haskoki-0.3.0.0.tar.gz` | Source distribution |
| `test-results-0.3.0.0.tar.gz` | Staged test evidence |
| `release-manifest.json` | Source revision, artifact hashes, build information, image digest |
| `SHA256SUMS` | Checksums of the three archives and manifest |
| `SHA256SUMS.asc` | Detached signature of the checksum file |

Publication is not atomic: the workflow pushes image tags before creating
the release, and creates the release before uploading its assets. If it
fails partway, inspect the registry, release assets, and run logs first.
The job refuses to replace an existing release. Do not announce, force-move
the source tag, or blindly rerun an incomplete publication; the owner must
decide how to finish or withdraw it.

The manifest's `source.dirty` includes untracked packaging files. In the
current workflow it may be true even for an unchanged tagged source;
inspect the recorded SHA and CI checkout before interpreting that field.

## Check the experience before announcing

Download all six assets into a fresh directory. After importing the public
key from the documented trusted location and checking its fingerprint:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

Expect a valid signature from that key and four `OK` checksums. Then use
a fresh Docker client configuration to test anonymous access:

```sh
HASKOKI_DOCKER_CONFIG=$(mktemp -d)
docker --config "$HASKOKI_DOCKER_CONFIG" pull ghcr.io/mingulov/haskoki-demo:v0.3.0.0
docker image inspect ghcr.io/mingulov/haskoki-demo:v0.3.0.0 \
  --format '{{json .RepoDigests}}'
```

Compare the repository digest with `release-manifest.json`. Run the
[demo, direct smoke, and proxy example](try-it.md) using this pulled image
name. Check the reports and verify archive installation against the
[host requirements](../SUPPORTED-HOSTS.md). Record the release URL, tag
SHA, image digest, and observed results.

Only then switch the README to the pull-and-run command and announce it.
Keep the source-build route available. Hackage and Docker Hub publication
are optional later work; neither is needed for this demo.
