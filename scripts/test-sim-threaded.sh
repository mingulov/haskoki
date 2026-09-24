#!/bin/sh
# scripts/test-sim-threaded.sh -- threaded native proof driver.
#
# Compiles tests/c/sim_threaded.c against the pinned 3.2 header family
# (3.2 header; newer-API surface, never provider-generated types) and runs
# it against the built shared module: N worker threads drive mixed
# session-churn/digest/event/control load while asserting conservation
# invariants (per-thread opens == closes, every call a legal code,
# final quiet-module smoke). Any crash, hang, or illegal return code
# is a FAIL.
#
# Usage:
#   scripts/test-sim-threaded.sh             # build scenario, run (must PASS)
#
# Tuning (window sizing only; defaults are the pinned N=4, M=50):
#   HASKOKI_SIM_N / HASKOKI_SIM_M / HASKOKI_SIM_ITERS
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-sim-threaded.sh
#
# Exit status: 0 iff the threaded probe passes.
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
if grep -rn "abi_generated\|abi_stubs\|abi-inventory" tests/c/sim_threaded.c 2>/dev/null; then
  fail "probe independence violated (see grep hits above)"
fi
echo "STATIC: sim probe does not include provider-generated artifacts"

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

# 2. Timeout-mapping self-test: prove timeout(1) maps a hung child to
#    exit 124 in THIS environment, so the guard below is load-bearing.
timeout 1 sleep 5 >/dev/null 2>&1
MAP_RC=$?
if [ "$MAP_RC" -ne 124 ]; then
  fail "timeout(1) self-test: expected 124 for a hung child, got $MAP_RC"
fi
echo "STATIC: timeout(1) hang -> 124 mapping proven (self-test)"

TMPD="${TMPDIR:-/tmp}/haskoki-sim"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

BIN="$TMPD/sim_threaded"
cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  -Ispec/vendor \
  -o "$BIN" tests/c/sim_threaded.c -ldl -lpthread \
  || fail "sim_threaded did not compile"
echo "probe compiled: $BIN (headers: spec/vendor)"

timeout 240 "$BIN" "$SO"
BIN_RC=$?
if [ "$BIN_RC" -eq 124 ]; then
  fail "sim_threaded TIMED OUT after 240s (hang guard fired; deadlock or stranding)"
fi
if [ "$BIN_RC" -ne 0 ]; then
  fail "sim_threaded reported failures (exit $BIN_RC)"
fi

echo "PASS: test-sim-threaded.sh (threaded native proof)"
