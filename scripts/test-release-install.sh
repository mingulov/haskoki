#!/bin/sh
# scripts/test-release-install.sh -- clean-container install test.
#
# Two legs, both on a BARE image (default ubuntu:26.04 — no GHC, no
# toolchain, only documented system deps installed):
#
#   Leg A (prepared tree): mounts the make-release.sh output tree at
#   /art and verifies:
#     1. ldd over the artifact lib/ shows ZERO "not found" with a
#        CLEAN environment (LD_LIBRARY_PATH unset — the module's
#        $ORIGIN RUNPATH resolves the bundled closure, and every
#        libHS* must resolve INSIDE $ART/lib, never from the host)
#     2. the shipped legacy provider (ossl-modules/legacy.so, plus
#        libcrypto.so.4 on module builds) resolves with zero
#        "not found" and binds inside /art/lib (no /opt on the
#        bare image)
#     3. haskoki-ctl --version runs
#     4. release_smoke (compiled in-container from the artifact's own
#        smoke/ sources with the in-container gcc) reports SMOKE-OK:
#        dlopen + init + metadata + REAL FIPS digest + DES-ECB legacy
#        KAT (proves the shipped provider executes) + finalize
#
#   Leg B (downloadable archive): extracts the DOWNLOADABLE bundle
#   archive (scripts/package-release.sh output, not a prepared tree)
#   inside the bare image to a path WITH SPACES, installs ONLY the
#   runtime system libraries (no compiler in this leg), and verifies
#   the same closure/provider/ctl/smoke contract using a PREBUILT
#   consumer binary (compiled on the host before the container
#   starts). The leg also asserts the consumer environment carries
#   no Haskell/Rust/Python toolchain.
#
# Usage (from haskoki/, on the HOST — this script drives docker):
#   scripts/test-release-install.sh [artifact-dir] [image] [bundle-tarball]
#   defaults: dist-release/haskoki-<ver from cabal>  ubuntu:26.04
#             dist-release/haskoki-<ver>-linux-x86_64.tar.gz
#
# All artifact paths are normalized to absolute paths before any
# docker mount. The missing-tarball case fails loudly (leg B needs
# the packaged archive; run scripts/package-release.sh first).
#
# The inner docker runs honor the standing hard rules themselves
# (timeout -s KILL + --network host — default-bridge DNS is dead in
# this environment, so the flag is what lets the in-container apt
# reach the network), and an apt failure fails loudly with a clear
# message instead of falling through to `cc: not found`.
#
# Exit status: 0 iff both legs pass on the bare image.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

VER=$(grep -m1 '^version:' haskoki.cabal | awk '{print $2}')
[ -n "$VER" ] || fail "cannot parse version from haskoki.cabal"
ART="${1:-dist-release/haskoki-$VER}"
IMAGE="${2:-ubuntu:26.04}"
TARBALL="${3:-dist-release/haskoki-$VER-linux-x86_64.tar.gz}"
case "$ART" in
  /*) ART_ABS="$ART" ;;
  *) ART_ABS="$PWD/$ART" ;;
esac
case "$TARBALL" in
  /*) TAR_ABS="$TARBALL" ;;
  *) TAR_ABS="$PWD/$TARBALL" ;;
esac
[ -f "$ART_ABS/lib/libhaskoki.so" ] || fail "artifact missing: $ART_ABS (run: scripts/make-release.sh)"
[ -f "$ART_ABS/smoke/release_smoke.c" ] || fail "artifact smoke missing: $ART_ABS"
[ -x "$ART_ABS/bin/haskoki-ctl" ] || fail "artifact ctl missing: $ART_ABS"
[ -f "$TAR_ABS" ] || fail "downloadable bundle archive missing: $TAR_ABS (run: scripts/package-release.sh)"
command -v docker >/dev/null 2>&1 || fail "docker required (host invocation)"
command -v cc >/dev/null 2>&1 || fail "host cc required (prebuilt consumer for leg B)"

echo "artifact under test: $ART_ABS"
echo "bundle archive under test: $TAR_ABS"
echo "bare image: $IMAGE"

echo "=== leg A: prepared tree ==="
timeout -s KILL 300 docker run --rm --network host \
  -v "$ART_ABS:/art:ro" \
  "$IMAGE" sh -c '
    set -u
    echo "--- container: $(cat /etc/os-release 2>/dev/null | grep -m1 PRETTY_NAME) / $(ldd --version | head -1)"
    echo "--- installing documented deps (gcc for smoke build, libgmp10/libffi8/libnuma1 system libs):"
    if ! apt-get update -qq > /tmp/apt-update.log 2>&1; then
      echo "FAIL: apt-get failed (update step; network or image drift — see tail below)"
      tail -5 /tmp/apt-update.log
      exit 1
    fi
    tail -1 /tmp/apt-update.log
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libc6-dev libgmp10 libffi8 libnuma1 > /tmp/apt-install.log 2>&1; then
      echo "FAIL: apt-get failed (install step; cannot build the smoke in-container — see tail below)"
      tail -5 /tmp/apt-install.log
      exit 1
    fi
    tail -1 /tmp/apt-install.log
    unset LD_LIBRARY_PATH
    echo "--- env hygiene: LD_LIBRARY_PATH=[${LD_LIBRARY_PATH-unset}] (must be unset)"
    [ -z "${LD_LIBRARY_PATH:-}" ] || { echo "FAIL: LD_LIBRARY_PATH leaked into the proof env"; exit 1; }
    echo "--- ldd closure check (no LD_LIBRARY_PATH; \$ORIGIN must resolve):"
    if ldd /art/lib/libhaskoki.so | grep "not found"; then
      echo "FAIL: unresolved libs in artifact closure"
      exit 1
    fi
    echo "ldd: zero unresolved"
    echo "--- closure provenance (every libHS* must resolve inside /art/lib):"
    if ldd /art/lib/libhaskoki.so | grep "libHS.*=>" | grep -v "/art/lib/"; then
      echo "FAIL: bundled lib resolved outside the artifact"
      exit 1
    fi
    echo "closure: all libHS* resolve inside /art/lib"
    echo "--- provider closure check (shipped legacy module, no /opt):"
    [ -f /art/lib/ossl-modules/legacy.so ] || { echo "FAIL: shipped legacy.so missing from artifact"; exit 1; }
    if ldd /art/lib/ossl-modules/legacy.so | grep "not found"; then
      echo "FAIL: unresolved libs in shipped provider closure"
      exit 1
    fi
    if ldd /art/lib/ossl-modules/legacy.so | grep -q "libcrypto"; then
      [ -f /art/lib/libcrypto.so.4 ] || { echo "FAIL: shipped libcrypto.so.4 missing from artifact"; exit 1; }
      if ldd /art/lib/ossl-modules/legacy.so | grep "libcrypto.*=>" | grep -v "/art/lib/"; then
        echo "FAIL: shipped legacy.so binds libcrypto outside the artifact"
        exit 1
      fi
      echo "provider closure: legacy.so binds libcrypto inside /art/lib"
    else
      echo "provider closure: legacy.so self-contained (no libcrypto dep)"
    fi
    echo "--- haskoki-ctl:"
    /art/bin/haskoki-ctl --version || exit 1
    echo "--- compiling bundled smoke:"
    cc -std=c11 -O2 -g -Wall -Wextra -Werror -I/art/smoke/include \
      -o /tmp/release_smoke /art/smoke/release_smoke.c -ldl || exit 1
    echo "--- running smoke:"
    /tmp/release_smoke /art/lib/libhaskoki.so || exit 1
  ' || fail "install test leg A failed on $IMAGE"
echo "leg A passing (prepared tree)"

echo "=== leg B: downloadable archive + space path + prebuilt consumer ==="
TMPD=$(mktemp -d) || fail "cannot create temp dir"
trap 'rm -rf "$TMPD"' EXIT INT TERM
PREBUILT="$TMPD/release_smoke_prebuilt"
echo "--- compiling prebuilt consumer on the host (outside the runtime env):"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -I"$ART_ABS/smoke/include" \
  -o "$PREBUILT" "$ART_ABS/smoke/release_smoke.c" -ldl \
  || fail "prebuilt consumer compile failed"
echo "prebuilt consumer: $PREBUILT"
timeout -s KILL 300 docker run --rm --network host \
  -v "$TAR_ABS:/bundle.tar.gz:ro" \
  -v "$PREBUILT:/consumer_smoke:ro" \
  "$IMAGE" sh -c '
    set -u
    echo "--- container: $(cat /etc/os-release 2>/dev/null | grep -m1 PRETTY_NAME) / $(ldd --version | head -1)"
    echo "--- installing RUNTIME-ONLY deps (system libs; no compiler in this leg):"
    if ! apt-get update -qq > /tmp/apt-update.log 2>&1; then
      echo "FAIL: apt-get failed (update step; network or image drift — see tail below)"
      tail -5 /tmp/apt-update.log
      exit 1
    fi
    tail -1 /tmp/apt-update.log
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libgmp10 libffi8 libnuma1 > /tmp/apt-install.log 2>&1; then
      echo "FAIL: apt-get failed (install step; cannot install runtime libs — see tail below)"
      tail -5 /tmp/apt-install.log
      exit 1
    fi
    tail -1 /tmp/apt-install.log
    unset LD_LIBRARY_PATH
    echo "--- env hygiene: LD_LIBRARY_PATH=[${LD_LIBRARY_PATH-unset}] (must be unset)"
    [ -z "${LD_LIBRARY_PATH:-}" ] || { echo "FAIL: LD_LIBRARY_PATH leaked into the proof env"; exit 1; }
    echo "--- toolchain absence (runtime-only consumer env):"
    for t in cc gcc ghc cabal rustc cargo python3 python; do
      if command -v "$t" >/dev/null 2>&1; then
        echo "FAIL: $t present in the runtime-only consumer env"
        exit 1
      fi
    done
    echo "toolchain absent: cc/gcc/ghc/cabal/rustc/python all missing, as required"
    echo "--- extracting downloadable archive to a path with spaces:"
    mkdir -p "/art space" || exit 1
    tar xzf /bundle.tar.gz -C "/art space" || exit 1
    BUNDLE=$(ls -d "/art space"/haskoki-* 2>/dev/null) || exit 1
    [ -f "$BUNDLE/lib/libhaskoki.so" ] || { echo "FAIL: extracted bundle lacks lib/libhaskoki.so"; exit 1; }
    echo "extracted bundle: $BUNDLE"
    echo "--- ldd closure check (no LD_LIBRARY_PATH; \$ORIGIN must resolve):"
    if ldd "$BUNDLE/lib/libhaskoki.so" | grep "not found"; then
      echo "FAIL: unresolved libs in extracted bundle closure"
      exit 1
    fi
    echo "ldd: zero unresolved"
    echo "--- closure provenance (every libHS* must resolve inside the bundle):"
    if ldd "$BUNDLE/lib/libhaskoki.so" | grep "libHS.*=>" | grep -v "/art space/"; then
      echo "FAIL: bundled lib resolved outside the extracted bundle"
      exit 1
    fi
    echo "closure: all libHS* resolve inside the extracted bundle"
    echo "--- provider closure check (shipped legacy module, no /opt):"
    [ -f "$BUNDLE/lib/ossl-modules/legacy.so" ] || { echo "FAIL: shipped legacy.so missing from extracted bundle"; exit 1; }
    if ldd "$BUNDLE/lib/ossl-modules/legacy.so" | grep "not found"; then
      echo "FAIL: unresolved libs in shipped provider closure"
      exit 1
    fi
    if ldd "$BUNDLE/lib/ossl-modules/legacy.so" | grep -q "libcrypto"; then
      [ -f "$BUNDLE/lib/libcrypto.so.4" ] || { echo "FAIL: shipped libcrypto.so.4 missing from extracted bundle"; exit 1; }
      if ldd "$BUNDLE/lib/ossl-modules/legacy.so" | grep "libcrypto.*=>" | grep -v "/art space/"; then
        echo "FAIL: shipped legacy.so binds libcrypto outside the extracted bundle"
        exit 1
      fi
      echo "provider closure: legacy.so binds libcrypto inside the extracted bundle"
    else
      echo "provider closure: legacy.so self-contained (no libcrypto dep)"
    fi
    echo "--- haskoki-ctl:"
    "$BUNDLE/bin/haskoki-ctl" --version || exit 1
    echo "--- running prebuilt consumer against the space path:"
    /consumer_smoke "$BUNDLE/lib/libhaskoki.so" || exit 1
  ' || fail "install test leg B failed on $IMAGE"
echo "leg B passing (downloadable archive + space path + prebuilt consumer)"

echo "PASS: test-release-install.sh (legs A+B passing on the bare image)"
