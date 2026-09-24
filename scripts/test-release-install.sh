#!/bin/sh
# scripts/test-release-install.sh -- clean-container install test.
#
# Unpacks the release artifact (scripts/make-release.sh output) on a
# BARE image (default ubuntu:26.04 — no GHC, no toolchain, only
# documented system deps installed) and verifies:
#   1. ldd over the artifact lib/ shows ZERO "not found" with a
#      CLEAN environment (LD_LIBRARY_PATH unset — the module's
#      $ORIGIN RUNPATH resolves the bundled closure, and every
#      libHS* must resolve INSIDE $ART/lib, never from the host)
#   2. haskoki-ctl --version runs
#   3. release_smoke (compiled in-container from the artifact's own
#      smoke/ sources with the in-container gcc) reports SMOKE-OK:
#      dlopen + init + metadata + REAL FIPS digest + finalize
#
# Usage (from haskoki/, on the HOST — this script drives docker):
#   scripts/test-release-install.sh [artifact-dir] [image]
#   defaults: dist-release/haskoki-<ver from cabal>  ubuntu:26.04
#
# The inner docker run honors the standing hard rules itself
# (timeout -s KILL + --network host — default-bridge DNS is dead in
# this environment, so the flag is what lets the in-container apt
# reach the network), and an apt failure fails loudly with a clear
# message instead of falling through to `cc: not found`.
#
# Exit status: 0 iff the install test passes on the bare image.
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
[ -f "$ART/lib/libhaskoki.so" ] || fail "artifact missing: $ART (run: scripts/make-release.sh)"
[ -f "$ART/smoke/release_smoke.c" ] || fail "artifact smoke missing: $ART"
[ -x "$ART/bin/haskoki-ctl" ] || fail "artifact ctl missing: $ART"
command -v docker >/dev/null 2>&1 || fail "docker required (host invocation)"

echo "artifact under test: $ART"
echo "bare image: $IMAGE"
timeout -s KILL 300 docker run --rm --network host \
  -v "$PWD/$ART:/art:ro" \
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
    echo "--- haskoki-ctl:"
    /art/bin/haskoki-ctl --version || exit 1
    echo "--- compiling bundled smoke:"
    cc -std=c11 -O2 -g -Wall -Wextra -Werror -I/art/smoke/include \
      -o /tmp/release_smoke /art/smoke/release_smoke.c -ldl || exit 1
    echo "--- running smoke:"
    /tmp/release_smoke /art/lib/libhaskoki.so || exit 1
  ' || fail "install test failed on $IMAGE"

echo "PASS: test-release-install.sh (clean-container install passing)"
