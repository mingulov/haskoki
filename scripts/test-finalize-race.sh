#!/bin/sh
# scripts/test-finalize-race.sh -- finalize-vs-entrant race driver.
#
# Compiles tests/c/finalize_race.c against the pinned 3.2 header family
# (3.2 header; newer-API surface, never provider-generated types) and runs
# it against the built shared module: N worker threads hammer cheap
# routed entries while one finalizer thread cycles C_Initialize/
# C_Finalize. Any crash, hang, or illegal return code is a FAIL.
#
# Usage:
#   scripts/test-finalize-race.sh             # build scenario, run (must PASS)
#
# Tuning (window sizing only; defaults are the pinned N=4, M=50):
#   HASKOKI_RACE_N / HASKOKI_RACE_M / HASKOKI_RACE_ITERS
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-finalize-race.sh
#
# Exit status: 0 iff the race probe passes.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

cabal build all || fail "cabal build all failed"

# 0. Independence guard: the probe must never consume
#    provider-generated orderings; it uses pinned vendor headers only.
if grep -rn "abi_generated\|abi_stubs\|abi-inventory" tests/c/finalize_race.c 2>/dev/null; then
  fail "probe independence violated (see grep hits above)"
fi
echo "STATIC: race probe does not include provider-generated artifacts"

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

TMPD="${TMPDIR:-/tmp}/haskoki-finalize-race"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

BIN="$TMPD/finalize_race"
cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  -Ispec/vendor \
  -o "$BIN" tests/c/finalize_race.c -ldl -lpthread \
  || fail "finalize_race did not compile"
echo "probe compiled: $BIN (headers: spec/vendor)"

"$BIN" "$SO" || fail "finalize_race reported failures"

echo "PASS: test-finalize-race.sh (finalize-vs-entrant race probe)"
