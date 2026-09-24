#!/bin/sh
# scripts/test-async-attached.sh — attached-async C proof driver.
#
# Builds the shared module in-container (`cabal build all`, incremental
# over the bind-mounted dist-newstyle), then compiles
# tests/c/async_attached.c as an independent non-Haskell executable
# and runs it against the built .so.
#
# The in-container build is load-bearing, not convenience: the module
# links Haskell dependencies (including direct-sqlite) whose shared
# objects live in the container's ephemeral cabal store, so only a
# module built in THIS container is guaranteed dlopenable here (its
# RUNPATH names this container's store).
#
#   Run (from haskoki/):
#     docker run --rm -v "$PWD:/work" -w /work \
#       haskoki-dev:ghc-9.10.3 scripts/test-async-attached.sh
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

cabal build all || fail "cabal build all failed"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
if [ -z "$SO_LIST" ]; then
  fail "no loadable module found (run: cabal build all)"
fi
if [ "$SO_COUNT" -ne 1 ]; then
  echo "found candidates:"
  echo "$SO_LIST"
  fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
fi
SO="$SO_LIST"
echo "module under test: $SO"

BIN="${TMPDIR:-/tmp}/haskoki-async-attached"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -o "$BIN" tests/c/async_attached.c -ldl \
  || fail "C proof harness did not compile"
echo "harness compiled: $BIN"

"$BIN" "$SO" || fail "C proof harness reported failures"

echo "PASS: test-async-attached.sh"
