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
#
# Usage (from haskoki/, on the HOST):
#   scripts/package-release.sh [out-dir]
# Env:
#   HASKOKI_RELEASE_DIR  output dir (default dist-release)
#   TEST_RESULTS_DIR     staged results dir (default $OUT/test-results-<ver>)
#   HASKOKI_IMAGE        builder image for the env record
#                        (default haskoki-dev:ghc-9.10.3)
#
# Exit status: 0 iff every asset is written and SHA256SUMS verifies.
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
command -v docker >/dev/null 2>&1 || fail "docker required (builder image identity)"
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
IMAGE_ID=$(docker inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null) \
  || fail "cannot inspect builder image: $IMAGE"
IMAGE_DIGEST=$(docker inspect "$IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null)
case "$IMAGE_DIGEST" in
  ""|"<no value>") IMAGE_DIGEST_JSON=null ;;
  *)
    # A RepoDigest whose digest part equals the local image (config)
    # ID is the daemon echoing the ID for an unpushed image, not a
    # repository (manifest) digest; record null and keep the ID
    # separate rather than mislabeling it.
    if [ "${IMAGE_DIGEST##*@}" = "$IMAGE_ID" ]; then
      IMAGE_DIGEST_JSON=null
    else
      IMAGE_DIGEST_JSON="\"$IMAGE_DIGEST\""
    fi ;;
esac
HOST_ABI=$(uname -srm)
GHC_V=$(docker run --rm "$IMAGE" ghc --numeric-version 2>/dev/null) \
  || fail "cannot read GHC version from $IMAGE"
CABAL_V=$(docker run --rm "$IMAGE" cabal --numeric-version 2>/dev/null) \
  || fail "cannot read cabal version from $IMAGE"
GCC_V=$(docker run --rm "$IMAGE" sh -c 'gcc -dumpversion' 2>/dev/null) \
  || fail "cannot read gcc version from $IMAGE"
GLIBC_V=$(docker run --rm "$IMAGE" sh -c 'ldd --version | head -1' 2>/dev/null) \
  || fail "cannot read glibc version from $IMAGE"
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
  echo "    \"checker\": {\"repo\": \"mingulov/pkcs11-check\", \"release\": \"v0.2.2\", \"tag_sha\": \"23813a5bc84f5763d4ec20b06f99429339f296be\", \"qualified\": false, \"note\": \"declared; re-verify in the checker task\"},"
  echo "    \"proxy_regression\": {\"repo\": \"mingulov/pkcs11-proxy-ng\", \"commit\": \"a48b60ba54b0163f4999c1e4fc0514bf7dc01681\", \"qualified\": false, \"note\": \"declared; re-qualify in the proxy task\"},"
  echo "    \"proxy_demo\": {\"repo\": \"mingulov/pkcs11-proxy-ng\", \"release\": \"v0.2.0\", \"tag_sha\": \"b298b0cd0f59d3e6b42518fc7a4aa5be51761c9d\", \"qualified\": false, \"note\": \"declared; qualify in the proxy task\"}"
  echo "  },"
  echo "  \"gate_evidence\": {"
  echo "    \"bundle\": [\"haskoki-$VER/closure/review.txt\", \"haskoki-$VER/toolchain-record.txt\"],"
  echo "    \"test_results\": $RESULTS_JSON"
  echo "  },"
  echo "  \"oci_digest\": null,"
  echo "  \"oci_note\": \"added later without a rebuild\""
  echo "}"
} > "$MANIFEST" || fail "manifest write failed"
python3 -m json.tool "$MANIFEST" > /dev/null || fail "manifest is not valid JSON"

(cd "$OUT" && sha256sum "$(basename "$BUNDLE_ARC")" "$(basename "$SDIST_ARC")" \
  "$(basename "$RESULTS_ARC")" "$(basename "$MANIFEST")" > "$(basename "$SUMS")") \
  || fail "SHA256SUMS write failed"
(cd "$OUT" && sha256sum -c "$(basename "$SUMS")") || fail "SHA256SUMS self-verify failed"

echo "assets:"
ls -la "$BUNDLE_ARC" "$SDIST_ARC" "$RESULTS_ARC" "$MANIFEST" "$SUMS"
cat "$SUMS"
echo "PASS: package-release.sh (5 assets + verified checksums)"
