#!/bin/sh
# scripts/package-release.sh -- downloadable-asset packager (thin wrapper).
#
# Archives the verified release inputs into downloadable assets. This
# script builds NOTHING (no second builder): every input must already
# exist and be verified, otherwise it fails loudly.
#
# Inputs (all required):
#   $OUT/haskoki-<ver>/              make-release.sh bundle tree (verified
#                                    by scripts/test-release-install.sh)
#   dist-newstyle/sdist/haskoki-<ver>.tar.gz
#                                    verified sdist (unpacked + built +
#                                    tested outside the checkout per
#                                    docs/toolchain.md before packaging)
#   $TEST_RESULTS_DIR                test-result logs staged for the
#                                    compact results archive (default
#                                    $OUT/test-results-<ver>/; must be
#                                    non-empty)
#
# Outputs (in $OUT, default dist-release/):
#   haskoki-<ver>-linux-x86_64.tar.gz   the bundle tree
#   haskoki-<ver>.tar.gz                the verified sdist (copied)
#   test-results-<ver>.tar.gz           the staged test-result logs
#   release-manifest.json               source SHA, versions, build env,
#                                       artifact hashes, tool pins, gate
#                                       evidence links (NO self-hash;
#                                       the OCI digest is added later
#                                       without a rebuild)
#   SHA256SUMS                          checksums of the four files above
#                                       (written after finalization,
#                                       excluding itself)
#   SHA256SUMS.asc                      detached armored OpenPGP signature
#                                       over SHA256SUMS (FINAL-4, OPTIONAL;
#                                       written only when HASKOKI_SIGNING_KEY
#                                       is set, AFTER the checksums finalize
#                                       and self-verify, then verified
#                                       in-script before success; absent
#                                       otherwise and the release ships
#                                       UNSIGNED with exit 0)
#
# Usage (from haskoki/, on the HOST):
#   scripts/package-release.sh [out-dir]
# Env:
#   HASKOKI_RELEASE_DIR  output dir (default dist-release)
#   TEST_RESULTS_DIR     staged results dir (default $OUT/test-results-<ver>)
#   HASKOKI_IMAGE        builder image for the env record
#                        (default haskoki-dev:ghc-9.10.3)
#   HASKOKI_OCI_DIGEST   pushed demo image digest for the manifest
#                        (default null; the publish path passes the
#                        digest it just pushed)
#   HASKOKI_PROVENANCE_FILE
#                        bundle-producer provenance JSON (written by
#                        the CI bundle job; when set, build_env comes
#                        from the producer instead of a local docker
#                        inspection, and docker is not required)
#   HASKOKI_BASE_DIGEST  demo-build ubuntu:26.04 digest (CI
#                        demo-image job output; default: resolve
#                        locally and mark packaging-time)
#   HASKOKI_RUST_DIGEST  demo-build rust:1.94-bookworm digest (CI
#                        demo-image job output; default: resolve
#                        locally and mark packaging-time)
#   HASKOKI_SIGNING_KEY  key id or fingerprint of the release signing
#                        key (OPTIONAL, FINAL-4). When set, SHA256SUMS
#                        is signed and the signature self-verified
#                        (any signing failure FAILS CLOSED, non-zero).
#                        When absent or empty the release ships
#                        UNSIGNED: checksums are still written and
#                        verified, no SHA256SUMS.asc is produced, and
#                        the exit status is still 0.
#                        Key provenance: the real release key is
#                        owner-controlled and provisioned out of band;
#                        at publish time the CI publish job imports it
#                        from the HASKOKI_RELEASE_SIGNING_KEY secret
#                        into an ephemeral GPG home (see the publish
#                        job), and the public verification key is
#                        published out-of-band (project site / release
#                        notes). Never commit key material. The key
#                        must be usable non-interactively (no
#                        passphrase prompt; loopback pinentry).
#
# Exit status: 0 iff every asset is written and SHA256SUMS verifies
# (plus, when HASKOKI_SIGNING_KEY is set, SHA256SUMS.asc is written
# and verifies with a Good signature).
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

# archive_dir <srcdir> <member> <outfile>: tar a member out of srcdir
# into a gzip archive with failure propagation at every stage. tar and
# gzip run as separate commands (a tar|gzip pipeline would report only
# gzip's status and hide tar failures), and the finished archive is
# list-verified before this function returns success.
archive_dir() {
  _adir="$1"; _amem="$2"; _aout="$3"
  _atmp="$_aout.tmp.$$"
  rm -f "$_atmp" "$_aout"
  (cd "$_adir" && tar -cf - "$_amem") > "$_atmp" \
    || { rm -f "$_atmp"; fail "tar failed: $_adir/$_amem"; }
  gzip -n < "$_atmp" > "$_aout" \
    || { rm -f "$_atmp" "$_aout"; fail "gzip failed: $_aout"; }
  rm -f "$_atmp"
  tar tzf "$_aout" > /dev/null \
    || { rm -f "$_aout"; fail "archive validation failed: $_aout"; }
}

VER=$(grep -m1 '^version:' haskoki.cabal | awk '{print $2}')
[ -n "$VER" ] || fail "cannot parse version from haskoki.cabal"
OUT="${1:-${HASKOKI_RELEASE_DIR:-dist-release}}"
TREE="$OUT/haskoki-$VER"
SDIST="dist-newstyle/sdist/haskoki-$VER.tar.gz"
RESULTS="${TEST_RESULTS_DIR:-$OUT/test-results-$VER}"
IMAGE="${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
if [ -z "${HASKOKI_PROVENANCE_FILE:-}" ]; then
  command -v docker >/dev/null 2>&1 || fail "docker required (builder image identity)"
fi
command -v python3 >/dev/null 2>&1 || fail "python3 required (manifest validation)"

# Required inputs (verified elsewhere; never built here).
[ -f "$TREE/lib/libhaskoki.so" ] || fail "bundle tree missing: $TREE (run: scripts/make-release.sh)"
[ -x "$TREE/bin/haskoki-ctl" ] || fail "bundle ctl missing: $TREE"
[ -f "$TREE/licenses/NOTICES.md" ] || fail "bundle notices missing: $TREE"
[ -f "$TREE/closure/review.txt" ] || fail "bundle review missing: $TREE"
[ -f "$TREE/toolchain-record.txt" ] || fail "bundle toolchain record missing: $TREE"
[ -f "$SDIST" ] || fail "verified sdist missing: $SDIST (run: cabal sdist, then verify per docs/toolchain.md)"
[ -d "$RESULTS" ] || fail "staged test results missing: $RESULTS"
[ -n "$(ls -A "$RESULTS" 2>/dev/null)" ] || fail "staged test results empty: $RESULTS"

BUNDLE_ARC="$OUT/haskoki-$VER-linux-x86_64.tar.gz"
SDIST_ARC="$OUT/haskoki-$VER.tar.gz"
RESULTS_ARC="$OUT/test-results-$VER.tar.gz"
MANIFEST="$OUT/release-manifest.json"
SUMS="$OUT/SHA256SUMS"

echo "packaging release assets into: $OUT"
archive_dir "$OUT" "haskoki-$VER" "$BUNDLE_ARC"
cp "$SDIST" "$SDIST_ARC" || fail "sdist copy failed"
RESBASE=$(basename "$RESULTS")
RESDIR=$(dirname "$RESULTS")
archive_dir "$RESDIR" "$RESBASE" "$RESULTS_ARC"

# Manifest inputs (all derived, nothing hand-typed except the
# declared tool pins recorded below with their qualification state).
SHA=$(git rev-parse HEAD 2>/dev/null || echo unknown)
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
if git diff --quiet 2>/dev/null && [ -z "$(git status --porcelain 2>/dev/null)" ]; then
  DIRTY=false
else
  DIRTY=true
fi
CLIENT_VER=$(grep -m1 '^version:' client/haskoki-client.cabal | awk '{print $2}')
[ -n "$CLIENT_VER" ] || fail "cannot parse version from client/haskoki-client.cabal"
if [ -n "${HASKOKI_PROVENANCE_FILE:-}" ]; then
  # Producer path (CI publish): build_env describes the bundle
  # job's build environment, not this packaging host.
  [ -f "$HASKOKI_PROVENANCE_FILE" ] \
    || fail "provenance file missing: $HASKOKI_PROVENANCE_FILE"
  IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["builder_image"])' \
    "$HASKOKI_PROVENANCE_FILE") || fail "cannot read builder_image from $HASKOKI_PROVENANCE_FILE"
  IMAGE_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["builder_image_id"])' \
    "$HASKOKI_PROVENANCE_FILE") || fail "cannot read builder_image_id from $HASKOKI_PROVENANCE_FILE"
  GHC_V=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ghc"])' \
    "$HASKOKI_PROVENANCE_FILE") || fail "cannot read ghc from $HASKOKI_PROVENANCE_FILE"
  CABAL_V=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cabal_install"])' \
    "$HASKOKI_PROVENANCE_FILE") || fail "cannot read cabal_install from $HASKOKI_PROVENANCE_FILE"
  GCC_V=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["gcc"])' \
    "$HASKOKI_PROVENANCE_FILE") || fail "cannot read gcc from $HASKOKI_PROVENANCE_FILE"
  GLIBC_V=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["builder_glibc"])' \
    "$HASKOKI_PROVENANCE_FILE") || fail "cannot read builder_glibc from $HASKOKI_PROVENANCE_FILE"
  [ -n "$IMAGE_ID" ] && [ -n "$GHC_V" ] \
    || fail "provenance file has empty fields: $HASKOKI_PROVENANCE_FILE"
  IMAGE_DIGEST_JSON=null
  ENV_PROVENANCE="bundle-producer ($HASKOKI_PROVENANCE_FILE)"
else
  IMAGE_ID=$(docker inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null) \
    || fail "cannot inspect builder image: $IMAGE"
  IMAGE_DIGEST=$(docker inspect "$IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null)
  case "$IMAGE_DIGEST" in
    ""|"<no value>") IMAGE_DIGEST_JSON=null ;;
    *)
      # A RepoDigest whose digest part equals the local image
      # ID is the daemon echoing the ID for an unpushed image,
      # not a repository (manifest) digest; record null and keep
      # the ID separate rather than mislabeling it. (The local
      # builder tag is never pushed, so null is always correct
      # here; the publish path selects pushed digests by repo
      # name instead — see the workflow's push step.)
      if [ "${IMAGE_DIGEST##*@}" = "$IMAGE_ID" ]; then
        IMAGE_DIGEST_JSON=null
      else
        IMAGE_DIGEST_JSON="\"$IMAGE_DIGEST\""
      fi ;;
  esac
  GHC_V=$(docker run --rm "$IMAGE" ghc --numeric-version 2>/dev/null) \
    || fail "cannot read GHC version from $IMAGE"
  CABAL_V=$(docker run --rm "$IMAGE" cabal --numeric-version 2>/dev/null) \
    || fail "cannot read cabal version from $IMAGE"
  GCC_V=$(docker run --rm "$IMAGE" sh -c 'gcc -dumpversion' 2>/dev/null) \
    || fail "cannot read gcc version from $IMAGE"
  GLIBC_V=$(docker run --rm "$IMAGE" sh -c 'ldd --version | head -1' 2>/dev/null) \
    || fail "cannot read glibc version from $IMAGE"
  ENV_PROVENANCE="packaging-time (local run; the publish path passes the bundle producer instead)"
fi
if [ -n "${HASKOKI_BASE_DIGEST:-}" ]; then
  BASE_DIGEST_JSON="\"$HASKOKI_BASE_DIGEST\""
  BASE_NOTE="demo runtime FROM; digest resolved at demo-image build time (job output)"
else
  BASE_DIGEST=$(docker inspect ubuntu:26.04 --format '{{index .RepoDigests 0}}' 2>/dev/null)
  case "$BASE_DIGEST" in
    ""|"<no value>") BASE_DIGEST_JSON=null ;;
    *) BASE_DIGEST_JSON="\"$BASE_DIGEST\"" ;;
  esac
  BASE_NOTE="demo runtime FROM; digest resolved at packaging time (local run)"
fi
if [ -n "${HASKOKI_RUST_DIGEST:-}" ]; then
  RUST_DIGEST_JSON="\"$HASKOKI_RUST_DIGEST\""
  RUST_NOTE="proxy toolchain FROM; digest resolved at demo-image build time (job output)"
else
  RUST_DIGEST=$(docker inspect rust:1.94-bookworm --format '{{index .RepoDigests 0}}' 2>/dev/null)
  case "$RUST_DIGEST" in
    ""|"<no value>") RUST_DIGEST_JSON=null ;;
    *) RUST_DIGEST_JSON="\"$RUST_DIGEST\"" ;;
  esac
  RUST_NOTE="proxy toolchain FROM; digest resolved at packaging time (local run)"
fi
HOST_ABI=$(uname -srm)
FREEZE_SHA=$(sha256sum cabal.project.freeze | awk '{print $1}')
LOCK_SHA=$(sha256sum toolchain.lock | awk '{print $1}')
OSSL_VER=$(grep -m1 '^version' toolchain.lock | awk '{print $3}')
OSSL_URL=$(grep -m1 '^tarball-url' toolchain.lock | awk '{print $3}')
OSSL_SHA=$(grep -m1 '^tarball-sha256' toolchain.lock | awk '{print $3}')
FLOOR=$(grep -m1 '^GLIBC_' "$TREE/closure/review.txt" | tr -d ' \t' || true)
[ -n "$FLOOR" ] || FLOOR=$(grep -o 'GLIBC_[0-9.]*' "$TREE/closure/review.txt" | sort -uV | tail -1)
BUNDLED_N=$(ls "$TREE"/lib/libHS*.so 2>/dev/null | wc -l)
if [ -f "$TREE/lib/libcrypto.so.4" ]; then PROVIDER_FILES="ossl-modules/legacy.so + libcrypto.so.4"; else PROVIDER_FILES="ossl-modules/legacy.so"; fi
BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_BYTES=$(wc -c < "$BUNDLE_ARC" | tr -d ' ')
BUNDLE_SHA=$(sha256sum "$BUNDLE_ARC" | awk '{print $1}')
SDIST_BYTES=$(wc -c < "$SDIST_ARC" | tr -d ' ')
SDIST_SHA=$(sha256sum "$SDIST_ARC" | awk '{print $1}')
RESULTS_BYTES=$(wc -c < "$RESULTS_ARC" | tr -d ' ')
RESULTS_SHA=$(sha256sum "$RESULTS_ARC" | awk '{print $1}')
# tar and python run separately (same pipeline-masking reason as
# archive_dir above); sorting happens in python so the order still
# matches `tar tzf | sort` for ASCII member names.
RESULTS_LIST=$(tar tzf "$RESULTS_ARC") || fail "cannot list test-results members"
[ -n "$RESULTS_LIST" ] || fail "test-results archive lists no members"
RESULTS_JSON=$(printf '%s\n' "$RESULTS_LIST" | python3 -c 'import sys,json; print(json.dumps(sorted(l.rstrip("\n") for l in sys.stdin)))')
[ -n "$RESULTS_JSON" ] || fail "cannot encode test-results members"

{
  echo "{"
  echo "  \"schema\": \"haskoki-release-manifest/1\","
  echo "  \"package\": \"haskoki\","
  echo "  \"version\": \"$VER\","
  echo "  \"client_version\": \"$CLIENT_VER\","
  echo "  \"built_utc\": \"$BUILT\","
  echo "  \"source\": {"
  echo "    \"sha\": \"$SHA\","
  echo "    \"branch\": \"$BRANCH\","
  echo "    \"dirty\": $DIRTY"
  echo "  },"
  echo "  \"build_env\": {"
  echo "    \"builder_image\": \"$IMAGE\","
  echo "    \"builder_image_id\": \"$IMAGE_ID\","
  echo "    \"builder_image_digest\": $IMAGE_DIGEST_JSON,"
  echo "    \"provenance\": \"$ENV_PROVENANCE\","
  echo "    \"host_abi\": \"$HOST_ABI\","
  echo "    \"ghc\": \"$GHC_V\","
  echo "    \"cabal_install\": \"$CABAL_V\","
  echo "    \"gcc\": \"$GCC_V\","
  echo "    \"builder_glibc\": \"$GLIBC_V\","
  echo "    \"freeze_sha256\": \"$FREEZE_SHA\","
  echo "    \"lock_sha256\": \"$LOCK_SHA\","
  echo "    \"lock_sha256_scope\": \"packaging-time (the bundle toolchain-record.txt carries the build-time snapshot)\""
  echo "  },"
  echo "  \"openssl\": {"
  echo "    \"version\": \"$OSSL_VER\","
  echo "    \"tarball_url\": \"$OSSL_URL\","
  echo "    \"tarball_sha256\": \"$OSSL_SHA\","
  echo "    \"linkage\": \"static libcrypto.a into lib/libhaskoki.so (option C: keep static link)\","
  echo "    \"provenance\": \"docs/toolchain.md (OpenSSL provenance + maintenance contract)\""
  echo "  },"
  echo "  \"bundle\": {"
  echo "    \"glibc_floor\": \"$FLOOR\","
  echo "    \"bundled_libHS\": $BUNDLED_N,"
  echo "    \"provider_files\": \"$PROVIDER_FILES\","
  echo "    \"closure_review\": \"haskoki-$VER/closure/review.txt\","
  echo "    \"toolchain_record\": \"haskoki-$VER/toolchain-record.txt\","
  echo "    \"install_notes\": \"haskoki-$VER/INSTALL.md\","
  echo "    \"notices\": \"haskoki-$VER/licenses/NOTICES.md\""
  echo "  },"
  echo "  \"artifacts\": {"
  echo "    \"bundle\": {\"file\": \"$(basename "$BUNDLE_ARC")\", \"bytes\": $BUNDLE_BYTES, \"sha256\": \"$BUNDLE_SHA\"},"
  echo "    \"sdist\": {\"file\": \"$(basename "$SDIST_ARC")\", \"bytes\": $SDIST_BYTES, \"sha256\": \"$SDIST_SHA\"},"
  echo "    \"test_results\": {\"file\": \"$(basename "$RESULTS_ARC")\", \"bytes\": $RESULTS_BYTES, \"sha256\": \"$RESULTS_SHA\"},"
  echo "    \"manifest\": {\"file\": \"$(basename "$MANIFEST")\", \"note\": \"no self-hash by design\"},"
  echo "    \"sha256sums\": {\"file\": \"$(basename "$SUMS")\", \"note\": \"written after finalization, excluding itself\"}"
  echo "  },"
  echo "  \"tool_pins\": {"
  echo "    \"checker\": {\"repo\": \"mingulov/pkcs11-check\", \"release\": \"v0.2.3\", \"tag_sha\": \"70f9796d62ca97043c77d27adfc82f5e50bc5d26\", \"pypi\": \"pkcs11-check==0.2.3\", \"qualified\": true, \"note\": \"R4 entrypoint pin (PyPI final; r4b rc1 proven code-identical, final re-proven by the driver)\"},"
  echo "    \"proxy_regression\": {\"repo\": \"mingulov/pkcs11-proxy-ng\", \"commit\": \"a48b60ba54b0163f4999c1e4fc0514bf7dc01681\", \"qualified\": false, \"note\": \"superseded by v0.2.0 in R5; kept as the R4 historical record\"},"
  echo "    \"proxy_demo\": {\"repo\": \"mingulov/pkcs11-proxy-ng\", \"release\": \"v0.2.2\", \"tag_sha\": \"e500cec9f4a8ef26decd854deae262b57477445d\", \"commit\": \"1ed7cc15c838de2e56ba03ac34f426847ffce049\", \"lock_sha256\": \"5452b6bd6ab47d72e8172a04a8f8a72460dabc17f66ced110b930f6d5d75b7d3\", \"qualified\": true, \"note\": \"R9 qualified (parity 70 holds + full checker lanes); supersedes R5 v0.2.0 pin; checked out by full commit SHA with fail-closed commit+lock+pair asserts (Dockerfile)\"}"
  echo "  },"
  echo "  \"gate_evidence\": {"
  echo "    \"bundle\": [\"haskoki-$VER/closure/review.txt\", \"haskoki-$VER/toolchain-record.txt\"],"
  echo "    \"test_results\": $RESULTS_JSON"
  echo "  },"
  if [ -n "${HASKOKI_OCI_DIGEST:-}" ]; then
    echo "  \"oci_digest\": \"$HASKOKI_OCI_DIGEST\","
    echo "  \"oci_note\": \"pushed demo image digest, passed in by the publish path\","
  else
    echo "  \"oci_digest\": null,"
    echo "  \"oci_note\": \"no HASKOKI_OCI_DIGEST supplied (local/staging package run)\","
  fi
  echo "  \"base_image\": {"
  echo "    \"ref\": \"ubuntu:26.04\","
  echo "    \"digest\": $BASE_DIGEST_JSON,"
  echo "    \"note\": \"$BASE_NOTE\""
  echo "  },"
  echo "  \"proxy_toolchain\": {"
  echo "    \"ref\": \"rust:1.94-bookworm\","
  echo "    \"digest\": $RUST_DIGEST_JSON,"
  echo "    \"note\": \"$RUST_NOTE\""
  echo "  },"
  echo "  \"ci_pin_policy\": \"external actions SHA-pinned with Dependabot bumps; ubuntu-latest runners and image tags float (see .github/workflows/ci.yml header)\","
  echo "  \"floating_inputs\": ["
  echo "    {\"input\": \"ubuntu-latest runners\", \"reason\": \"GitHub-managed, unpinnable by design\", \"effective\": \"not captured; lanes run containerized (pinned toolchain image) or assert exact outputs\"},"
  echo "    {\"input\": \"ubuntu:26.04 image tag\", \"reason\": \"base tag floats by policy; the effective digest is recorded per build\", \"effective\": \"base_image.digest\"},"
  echo "    {\"input\": \"rust:1.94-bookworm image tag\", \"reason\": \"proxy toolchain tag floats by policy; the effective digest is recorded per build\", \"effective\": \"proxy_toolchain.digest\"},"
  echo "    {\"input\": \"haskoki-dev:ghc-9.10.3 local tag\", \"reason\": \"rebuilt per CI run from the pinned Dockerfile, never pushed\", \"effective\": \"build_env.builder_image_id\"},"
  echo "    {\"input\": \"PyPI (checker venv)\", \"reason\": \"registry resolution at build time\", \"effective\": \"docker/checker-requirements.txt hash lock (all 33 distributions pinned with artifact hashes) installed with pip --require-hashes; the lock plus /opt/p11c/freeze.txt are baked into the image (FINAL-34)\"},"
  echo "    {\"input\": \"crates.io (proxy build)\", \"reason\": \"registry resolution at build time\", \"effective\": \"PROXY_COMMIT 1ed7cc15 plus Cargo.lock sha256 pin plus --locked build plus asserted daemon/shim hashes (Dockerfile)\"},"
  echo "    {\"input\": \"github.com git (proxy clone)\", \"reason\": \"source fetch at image build time\", \"effective\": \"PROXY_COMMIT full-SHA checkout with fail-closed commit check; tag_sha in tool_pins.proxy_demo is a label only\"},"
  echo "    {\"input\": \"APT repository/package resolution\", \"reason\": \"checker and runtime stages apt-install unversioned package names; the base digest does not identify them\", \"effective\": \"installed dpkg versions baked into the image, enumerated in docs/dependency-inventory.md\"}"
  echo "  ]"
  echo "}"
} > "$MANIFEST" || fail "manifest write failed"
python3 -m json.tool "$MANIFEST" > /dev/null || fail "manifest is not valid JSON"

(cd "$OUT" && sha256sum "$(basename "$BUNDLE_ARC")" "$(basename "$SDIST_ARC")" \
  "$(basename "$RESULTS_ARC")" "$(basename "$MANIFEST")" > "$(basename "$SUMS")") \
  || fail "SHA256SUMS write failed"
(cd "$OUT" && sha256sum -c "$(basename "$SUMS")") || fail "SHA256SUMS self-verify failed"

# Release authentication (FINAL-4, OPTIONAL): the checksums above are
# FINALIZED before this point — nothing below mutates the four
# checksummed files. When HASKOKI_SIGNING_KEY names a usable key,
# the detached signature is written only now, then verified
# in-script before success is reported; a missing gpg, a signing
# failure, or a verify failure all FAIL CLOSED (any stale/partial
# .asc is removed, never shipped). When the key is absent or empty
# the release ships UNSIGNED with exit 0 (checksums still written
# and verified, no .asc).
ASC="$OUT/SHA256SUMS.asc"
# A stale signature from an earlier run must never survive into a
# run it does not belong to: remove it before either branch below.
rm -f "$ASC"
if [ -n "${HASKOKI_SIGNING_KEY:-}" ]; then
  command -v gpg >/dev/null 2>&1 || fail "gpg required (SHA256SUMS signing)"
  gpg --batch --no-tty --pinentry-mode loopback --yes \
    --detach-sign --armor --local-user "$HASKOKI_SIGNING_KEY" \
    --output "$ASC" "$SUMS" \
    || { rm -f "$ASC"; fail "SHA256SUMS signing failed"; }
  gpg --batch --no-tty --verify "$ASC" "$SUMS" \
    || { rm -f "$ASC"; fail "SHA256SUMS.asc self-verify failed"; }
  SIGNED=yes
else
  echo "NOTE: HASKOKI_SIGNING_KEY is not set; shipping UNSIGNED (no SHA256SUMS.asc)"
  SIGNED=no
fi

echo "assets:"
if [ "$SIGNED" = yes ]; then
  ls -la "$BUNDLE_ARC" "$SDIST_ARC" "$RESULTS_ARC" "$MANIFEST" "$SUMS" "$ASC"
else
  ls -la "$BUNDLE_ARC" "$SDIST_ARC" "$RESULTS_ARC" "$MANIFEST" "$SUMS"
fi
cat "$SUMS"
if [ "$SIGNED" = yes ]; then
  echo "PASS: package-release.sh (6 assets + verified checksums + verified signature)"
else
  echo "PASS: package-release.sh (5 assets + verified checksums, UNSIGNED: no HASKOKI_SIGNING_KEY)"
fi
