# Publishing the demo

Use **Actions -> CI and Release -> Run workflow** to publish the demo.
Select **main**, set **mode** to **release**, and enter the exact Cabal
**version** without `v` (currently `0.3.0.0`). The default **build** mode
only builds and tests artifacts. A release always uses the selected
commit recorded by GitHub, even if main changes while the jobs run.

This is a publication recipe. As of 2026-10-09, a GitHub Release and
anonymous access to the GHCR image have not been verified. The successful
[October 8 CI run](https://github.com/mingulov/haskoki/actions/runs/37774745195)
validated the previous source, not this workflow or a public release.

## One-time owner setup

1. Integrate the reviewed workflow and release notes into main. Keep
   `haskoki.cabal`, demo entrypoint, Dockerfile version and release-note
   filename consistent. The release input must match those identities.
2. Add the repository Actions secret `HASKOKI_RELEASE_SIGNING_KEY`, containing
   the exported GPG private signing key. It must sign unattended with no
   passphrase prompt. Preflight imports it into a temporary keyring and
   proves signing works before starting the release builds. Never commit it.
3. Publish the corresponding public key and full fingerprint at an
   owner-controlled location, and link that location in the release notes.
   Checksums alone do not authenticate downloads.
4. Allow the workflow's requested release, package and attestation writes.
   It uses `GITHUB_TOKEN`; no extra PAT is required by this workflow.
5. After the first image push, check the
   [GHCR package settings](https://github.com/users/mingulov/packages/container/haskoki-demo/settings)
   and set visibility to **Public**. New packages normally start private;
   a public Git repository does not make its container public automatically.
   If the anonymous pull step stops the first run, change visibility and
   choose **Re-run failed jobs** in that same run.

Release mode retains the qualified fast-checker ref `v0.2.1`.
`framework_ref` overrides apply to build mode only. The image includes its
separately pinned checker `0.2.3` and proxy `v0.2.2`.

## What the release does

The read-only preflight validates main, version, source SHA, signing and
published releases. Draft discovery needs authenticated write visibility;
the publisher checks all release pages and exact tag/run/SHA ownership
before any remote writes. The workflow runs the required Haskell, C-driver,
bundle, source-package, fast-checker and demo-image jobs. It then loads the exact
tested demo image and uses the already verified bundle and source archive.
There is no second build or dispatch after creating the source tag.
A tag pushed with `GITHUB_TOKEN` need not trigger another workflow.

After local asset/signature checks, it creates `v0.3.0.0` on the checked
SHA, pushes the versioned image when absent, and verifies its configuration,
version/revision labels and registry digest. It requires an anonymous
pull by digest using a fresh Docker configuration, then runs the pulled
demo and direct smoke profile without external network access.

Before creating or uploading a draft, the workflow saves and verifies the
original signed files in an immutable same-run Actions checkpoint. A draft
GitHub Release receives these six files. The workflow downloads and checks
the uploaded bytes before creating provenance attestations, updating
`latest`, and publishing the draft:

| Asset | Purpose |
| --- | --- |
| `haskoki-0.3.0.0-linux-x86_64.tar.gz` | Native module, control tool, runtime libraries, licenses, smoke consumer |
| `haskoki-0.3.0.0.tar.gz` | Verified source distribution |
| `test-results-0.3.0.0.tar.gz` | Staged test evidence |
| `release-manifest.json` | Source SHA, hashes, build information, image digest |
| `SHA256SUMS` | Checksums of the three archives and manifest |
| `SHA256SUMS.asc` | Detached OpenPGP signature of the checksums |

The Actions summary records the release URL, source SHA and image digest.
The KAT/vector lane remains informational; a passing checker job can still
report findings. The C job is the existing deterministic subset. The full
native driver manifest has its separate `scripts/run-gates.sh` route.

The owner-pushed tag route also remains available: push an annotated
`v<VERSION>` tag matching Cabal to run the same publication job. Manual
release mode is the simplest UI route. Publication runs serialize with
one another, and ordinary CI pushes cannot cancel an active release.

## Failed runs and retries

Publication is not atomic. A failure may leave a source tag, versioned
image or draft. Inspect the failed step and remote state before retrying:

- For first-time private GHCR access, set the package to Public, then
  **Re-run failed jobs** in the original run. The existing tag must still
  resolve to the selected SHA, and the existing image must match that
  run's tested image ID and source labels. Neither is overwritten.
- For an owned draft, choose **Re-run failed jobs** in the original run.
  The publisher restores the original signed files from the Actions artifact
  `release-assets-<run_id>-<source_sha>`, retained for 90 days subject to
  repository retention policy. The checkpoint contains the six files and
  `release-checkpoint.json`; that metadata is not a GitHub Release asset.
  The downloaded member set, run/SHA/version/image identity, file hashes,
  signature and checked bundle/source archives must all match before use.
  An incomplete draft receives only missing files; existing bytes must match.
- The checkpoint is never overwritten on retry. Keep it until publication
  succeeds. A missing, expired, ambiguous or mismatched checkpoint for an
  existing draft stops the retry. Inspect the state and decide on withdrawal
  or a new version under owner control; the workflow cannot reconstruct lost
  signed files or take over a different run. Do not replace draft assets.
- A public release, foreign draft, changed tag or different image is
  refused. **Re-run all jobs** may rebuild different bytes because base
  images and package repositories float; it is not an identity-safe retry.
  A new workflow run cannot take over another run's draft.

Never force-move a version tag or blindly start another release. Existing
published versions are preserved. The manifest's `source.dirty` includes
untracked packaging inputs and can be true despite an unchanged checkout;
use its source SHA and the run's checked commit for identity.

## Verify the public experience

Download all six files into a new directory. Import the public key from
the trusted location in the notes and check its full fingerprint, then:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
HASKOKI_DOCKER_CONFIG=$(mktemp -d)
docker --config "$HASKOKI_DOCKER_CONFIG" pull ghcr.io/mingulov/haskoki-demo:v0.3.0.0
docker image inspect ghcr.io/mingulov/haskoki-demo:v0.3.0.0 \
  --format '{{json .RepoDigests}}'
rm -r "$HASKOKI_DOCKER_CONFIG"
```

Expect a signature from the documented key and four `OK` checksums. The
repository digest must match `release-manifest.json`. Run the
[demo, direct/proxy checks and exploration recipes](try-it.md#after-the-first-successful-release)
with that image. Verify the native archive against the
[host requirements](../SUPPORTED-HOSTS.md), and record the release URL,
tag SHA, digest and observed results before announcing it.

Hackage and Docker Hub publication are separate optional work.
