# Publishing the demo

Use **Actions -> CI and Release -> Run workflow** to publish the demo.
Select **main**, set **mode** to **release**, and enter the exact Cabal
**version** without `v` (matching `haskoki.cabal`).
The default **build** mode
only builds and tests artifacts. A release always uses the selected
commit recorded by GitHub, even if main changes while the jobs run.

The first release, [v0.3.0.0](https://github.com/mingulov/haskoki/releases/tag/v0.3.0.0),
was published on October 9, 2026. Its [release workflow](https://github.com/mingulov/haskoki/actions/runs/37961585654)
checked anonymous access. The second release,
[v0.3.1.0](https://github.com/mingulov/haskoki/releases/tag/v0.3.1.0),
was published on October 12, 2026 from source `a89fb09` (image digest
`sha256:4f8f152fd283aa9aec864eab18cb3eb2cb7ca7b1bae10875080721bb9c0587fe`,
five unsigned assets). The third release,
[v0.4.0.0](https://github.com/mingulov/haskoki/releases/tag/v0.4.0.0),
was published on October 15, 2026 from source `d35650d` (image digest
`sha256:9c1bef4b58a95373bbbdb979107a655e85f14e5a0acc80c04586c9df5dcd9c4f`, five unsigned assets;
[release run](https://github.com/mingulov/haskoki/actions/runs/38748844491), where one
intermittent storage test failure on the first attempt was re-run with
**Re-run failed jobs**). The fourth release,
[v0.5.0.0](https://github.com/mingulov/haskoki/releases/tag/v0.5.0.0),
was published on October 19, 2026 from source `091a222` (image digest
`sha256:2e0b73aacce0357fd8292608f1ac45cd8b81b6e3cf14c4dadba877c1fc801406`, five unsigned assets;
[release run](https://github.com/mingulov/haskoki/actions/runs/39198914304)).
Each new release must repeat those checks on its
own source and artifacts.

For **GitHub-only validation without publication**, open or update a pull
request. Each update runs CI and coverage once; automatic push builds cover
main and tags. To validate a branch before opening a PR, run **CI and Release**
with **mode=build** on that branch. CI builds the native bundle and demo image
and runs their checks. Download
`demo-image-tested` from a successful run if you want the candidate image
before publication; extract the artifact ZIP, then use `docker load -i
demo-image.tar.gz` and `docker run --rm --network none haskoki-demo:X.Y.Z.W`.
The `demo-image-candidate` artifact is produced before all tests finish;
use the tested artifact for a demo. No local compiler build is needed.

## One-time owner setup

1. Integrate the reviewed workflow and release notes into main. Keep
   `haskoki.cabal`, demo entrypoint, Dockerfile version and release-note
   filename consistent. The release input must match those identities.
2. Optionally add the repository Actions secret `HASKOKI_RELEASE_SIGNING_KEY`,
   containing the exported GPG private signing key. When present it must
   sign unattended with no passphrase prompt; preflight imports it into a
   temporary keyring and proves signing works before starting the release
   builds, and the release ships six assets including `SHA256SUMS.asc`.
   When absent the release ships unsigned (five assets) instead of
   refusing. Never commit the key either way.
3. When signing is used, publish the corresponding public key and full
   fingerprint at an owner-controlled location, and link that location
   in the release notes. Checksums alone do not authenticate downloads.
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

The read-only preflight validates main, version, source SHA and
published releases, and proves unattended signing when a key is
provisioned. Draft discovery needs authenticated write visibility;
the publisher checks all release pages and exact tag/run/SHA ownership
before any remote writes. The workflow runs the required Haskell, C-driver,
bundle, source-package, fast-checker and demo-image jobs. It then loads the exact
tested demo image and uses the already verified bundle and source archive.
The demo image is built once in `demo-image-build`. Three
`demo-image-shards` jobs load the saved candidate and run contracts, full
checks, and the real compare command in parallel. The required `demo-image`
gate rejects failed, cancelled, skipped or missing shards and verifies all
three tested the same source and image before promoting the saved bytes.
Reports keep separate `contracts/`, `full/` and `compare/` directories in
`demo-image-runs`; the publisher still consumes `demo-image-tested`.
For complete local verification, run `sh scripts/test-demo-image.sh` from
the repository root; it builds and runs all three groups in sequence.
The local release manifest (`scripts/release-evidence.sh`) runs the same
driver in four phases instead — `build`, then `contracts`, `full` and
`compare` against the frozen image id, each under its own 5400 s guard —
and records them as one `test-demo-image.sh` step, because the serial run
takes 84–113 min on v0.5.0.0 and outlasts a single 90-minute guard.

There is no second build or dispatch after creating the source tag.
A tag pushed with `GITHUB_TOKEN` need not trigger another workflow.

After local asset checks (plus signature checks when signed), it
creates the requested version tag on the checked SHA, pushes the versioned image when
absent, and verifies its configuration, version/revision labels and
registry digest. It requires an anonymous pull by digest using a fresh
Docker configuration, then runs the pulled demo and direct smoke
profile without external network access.

Before creating or uploading a draft, the workflow saves and verifies the
original files in an immutable same-run Actions checkpoint. A draft
GitHub Release receives these five files, six when the release is signed.
The workflow downloads and checks the uploaded bytes before creating
provenance attestations, updating `latest`, and publishing the draft:

| Asset | Purpose |
| --- | --- |
| `haskoki-X.Y.Z.W-linux-x86_64.tar.gz` | Native module, control tool, runtime libraries, licenses, smoke consumer |
| `haskoki-X.Y.Z.W.tar.gz` | Verified source distribution |
| `test-results-X.Y.Z.W.tar.gz` | Staged test evidence |
| `release-manifest.json` | Source SHA, hashes, build information, image digest |
| `SHA256SUMS` | Checksums of the three archives and manifest |
| `SHA256SUMS.asc` | Detached OpenPGP signature of the checksums (only when a signing key is provisioned) |

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
  The publisher restores the original files from the Actions artifact
  `release-assets-<run_id>-<source_sha>`, retained for 90 days subject to
  repository retention policy. The checkpoint contains the five files (six
  when signed) and `release-checkpoint.json`; that metadata is not a GitHub
  Release asset. The downloaded member set, run/SHA/version/image identity,
  file hashes, the signature when present, and checked bundle/source
  archives must all match before use. An incomplete draft receives only
  missing files; existing bytes must match.
- The checkpoint is never overwritten on retry. Keep it until publication
  succeeds. A missing, expired, ambiguous or mismatched checkpoint for an
  existing draft stops the retry. Inspect the state and decide on withdrawal
  or a new version under owner control; the workflow cannot reconstruct lost
  files or take over a different run. Do not replace draft assets.
- A public release, foreign draft, changed tag or different image is
  refused. **Re-run all jobs** may rebuild different bytes because base
  images and package repositories float; it is not an identity-safe retry.
  A new workflow run cannot take over another run's draft.

Never force-move a version tag or blindly start another release. Existing
published versions are preserved. The manifest's `source.dirty` includes
untracked packaging inputs and can be true despite an unchanged checkout;
use its source SHA and the run's checked commit for identity.

## Verify the public experience

Download all five files into a new directory (six when the release is
signed: `SHA256SUMS.asc` is present). For a signed release, import the
public key from the trusted location in the notes, check its full
fingerprint, and verify the signature first:

```sh
TAG=vX.Y.Z.W  # the release under verification
gpg --verify SHA256SUMS.asc SHA256SUMS  # signed releases only
sha256sum -c SHA256SUMS
HASKOKI_DOCKER_CONFIG=$(mktemp -d)
docker --config "$HASKOKI_DOCKER_CONFIG" pull ghcr.io/mingulov/haskoki-demo:$TAG
docker image inspect ghcr.io/mingulov/haskoki-demo:$TAG \
  --format '{{json .RepoDigests}}'
rm -r "$HASKOKI_DOCKER_CONFIG"
```

Expect four `OK` checksums (plus a signature from the documented key
on signed releases). The repository digest must match
`release-manifest.json`. Run the
[demo, direct/proxy checks and exploration recipes](try-it.md)
with that image. Verify the native archive against the
[host requirements](../SUPPORTED-HOSTS.md), and record the release URL,
tag SHA, digest and observed results before announcing it.

Hackage and Docker Hub publication are separate optional work.
