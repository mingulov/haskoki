#!/bin/sh
# scripts/test-ossl4-bounds.sh — ossl4 FFI regression proof (audit findings 1-3).
#
# Compiles tests/c/ossl4_bounds.c as an independent non-Haskell
# executable and runs it against the built shared module. The driver
# resolves the hsk_ossl4_* entry points directly and pins the success
# + error contracts of the findings-hardened helpers (AEAD GCM/CCM
# round-trips and error legs, DH KAT + error legs).
#
#   Run (from haskoki/):
#     scripts/test-ossl4-bounds.sh
#   (in the pinned toolchain image via bind mount, like the other
#   drivers:
#     docker run --rm -v "$PWD:/work" -w /work \
#       haskoki-dev:ghc-9.10.3 scripts/test-ossl4-bounds.sh)
#
# Exit status: 0 iff the C proof passes.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

# The driver needs only the shared module: build just the foreign
# library, not the world. Host checkouts stage the pinned OpenSSL 4
# prefix under lib64/ (the image uses lib/); pass it through when
# present so :libcrypto.a resolves in both places.
EXTRA_LIB_DIRS=""
if [ -d /opt/openssl-4.0.2/lib64 ]; then
  EXTRA_LIB_DIRS="--extra-lib-dirs=/opt/openssl-4.0.2/lib64"
fi
# shellcheck disable=SC2086
cabal build $EXTRA_LIB_DIRS foreign-library:haskoki \
  || fail "foreign-library build failed"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
if [ -z "$SO_LIST" ]; then
  fail "no loadable module found (foreign-library build produced none)"
fi
if [ "$SO_COUNT" -ne 1 ]; then
  echo "found candidates:"
  echo "$SO_LIST"
  fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
fi
SO="$SO_LIST"
echo "module under test: $SO"

BIN="${TMPDIR:-/tmp}/haskoki-ossl4-bounds"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -o "$BIN" tests/c/ossl4_bounds.c -ldl \
  || fail "C proof harness did not compile"
echo "harness compiled: $BIN"

"$BIN" "$SO" || fail "C proof harness reported failures"

echo "PASS: test-ossl4-bounds.sh"
