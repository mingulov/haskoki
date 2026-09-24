#!/bin/sh
# scripts/test-loader.sh — loader suite driver.
#
# Builds nothing: expects `cabal build` to have produced the shared module
# (run inside the Docker toolchain image via bind mount; see below).
# Compiles tests/c/loader.c as an independent non-Haskell executable,
# runs it against the built .so, then performs the no-hs_exit and
# loader-pinning static checks. Case A06a is the fork-child probe
# (fork + assert the SUPPORTED-HOSTS.md fork-safety stance); the
# loader proof's enforcement surface is pinned by
# scripts/check-fork-stance.py.
#
# NORM RECIPE: a loader norm is this script's full log
# with addresses normalized (0xADDR) AND the recorded-not-gated
# ldd-closure section removed (ldd-closure excluded): drop the
# "STATIC: ldd ..." line through the last closure line before
# "PASS: test-loader.sh". Link-shape changes (new DT_NEEDED
# entries) appear only inside the excluded section, so they never
# re-litigate 'byte-identical'; every other line compares exactly.
# (Change this recipe, never the transcripts.)
#
#   Run (from haskoki/):
#     docker run --rm -v "$PWD:/work" -w /work \
#       haskoki-dev:ghc-9.10.3 scripts/test-loader.sh
#
# Exit status: 0 iff the loader harness passes AND all static checks hold.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

cabal build all || fail "cabal build all failed"

# 1. Locate exactly one built shared module.
SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
if [ -z "$SO_LIST" ]; then
  fail "no loadable module found (expected dist-newstyle/.../libhaskoki*.so; run: cabal build all)"
fi
if [ "$SO_COUNT" -ne 1 ]; then
  echo "found candidates:"
  echo "$SO_LIST"
  fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
fi
SO="$SO_LIST"
echo "module under test: $SO"

# 2. Compile the independent harness (self-contained; needs only dl/pthread).
LOADER_BIN="${TMPDIR:-/tmp}/haskoki-loader"
cc -std=c11 -O2 -g -Wall -Wextra -o "$LOADER_BIN" tests/c/loader.c -ldl -lpthread \
  || fail "loader harness did not compile"
echo "harness compiled: $LOADER_BIN"

# 3. Run the harness (A01-A06 + SHA + stubs).
"$LOADER_BIN" "$SO" || fail "loader harness reported failures"

# 4. No-hs_exit checks: our sources must never CALL hs_exit, and our own
#    C objects must not reference the symbol at all. (Comments may name it.)
if grep -rnE 'hs_exit[[:space:]]*\(' cbits ffi; then
  fail "hs_exit call-site found in provider sources"
fi
echo "STATIC: no hs_exit call-site in cbits/ ffi/"

OUR_OBJS=$(find dist-newstyle -path '*cbits*' -name '*.o' 2>/dev/null)
if [ -z "$OUR_OBJS" ]; then
  fail "could not find provider cbits objects under dist-newstyle"
fi
if nm $OUR_OBJS 2>/dev/null | grep -i 'hs_exit'; then
  fail "hs_exit symbol referenced by provider cbits objects"
fi
echo "STATIC: no hs_exit reference in provider cbits objects"

# 5. Loader-pinning evidence: DF_1_NODELETE keeps Haskell code mapped
#    across dlclose (process-pinned embedding per 03-abi-and-runtime §6).
if command -v readelf >/dev/null 2>&1; then
  if readelf -d "$SO" | grep -i nodelete >/dev/null; then
    echo "STATIC: DF_1_NODELETE present (dlclose retention enforced)"
  else
    fail "DF_1_NODELETE missing from $SO (pinning strategy not applied)"
  fi
else
  echo "STATIC: readelf unavailable; skipping NODELETE check"
fi

# 6. Dependency closure (recorded, not gated beyond printability).
if command -v ldd >/dev/null 2>&1; then
  echo "STATIC: ldd $SO:"
  ldd "$SO" || fail "ldd failed on $SO"
fi

echo "PASS: test-loader.sh (harness + static checks)"
