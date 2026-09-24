#!/bin/sh
# scripts/test-async-detached.sh — detach/rejoin C proof driver.
#
# Builds the shared module in-container (`cabal build all`, incremental
# over the bind-mounted dist-newstyle), then compiles
# tests/c/async_detached.c (guard-page detach/rejoin) and
# tests/c/async_restart.c (two-process SQLite recovery) as independent
# non-Haskell executables and runs them against the built .so.
#
# The in-container build is load-bearing, not convenience: the module
# links Haskell dependencies (direct-sqlite) whose shared objects live
# in the container's ephemeral cabal store, so only a module built in
# THIS container is guaranteed dlopenable here (its RUNPATH names this
# container's store).
#
#   Run (from haskoki/):
#     docker run --rm -v "$PWD:/work" -w /work \
#       haskoki-dev:ghc-9.10.3 scripts/test-async-detached.sh
#
# Exit status: 0 iff every C proof passes.
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

BIN_DETACH="${TMPDIR:-/tmp}/haskoki-async-detached"
BIN_RESTART="${TMPDIR:-/tmp}/haskoki-async-restart"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -o "$BIN_DETACH" tests/c/async_detached.c -ldl \
  || fail "detach C proof harness did not compile"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -o "$BIN_RESTART" tests/c/async_restart.c -ldl \
  || fail "restart C proof harness did not compile"
echo "harnesses compiled: $BIN_DETACH $BIN_RESTART"

"$BIN_DETACH" "$SO" || fail "detach C proof harness reported failures"

# Two-process SQLite recovery: process A detaches + exits, process B
# opens the same DB file, rejoins, and completes.
RESTART_TMP=$(mktemp -d "${TMPDIR:-/tmp}/haskoki-async-restart.XXXXXX") \
  || fail "mktemp failed"
DB="$RESTART_TMP/jobs.db"
A_OUT="$RESTART_TMP/a.out"
"$BIN_RESTART" A "$SO" "$DB" >"$A_OUT" 2>&1 || {
  cat "$A_OUT"
  rm -rf "$RESTART_TMP"
  fail "restart process A reported failures"
}
cat "$A_OUT"
LINE=$(grep '^PID=' "$A_OUT" | tail -1)
PID=$(echo "$LINE" | sed 's/^PID=\([0-9]*\) HANDLE=.*$/\1/')
HANDLE=$(echo "$LINE" | sed 's/^PID=[0-9]* HANDLE=//')
if [ -z "$PID" ] || [ -z "$HANDLE" ]; then
  rm -rf "$RESTART_TMP"
  fail "process A did not report PID/HANDLE ($LINE)"
fi
echo "A detached persistent id $PID (old handle $HANDLE); B rejoins"
"$BIN_RESTART" B "$SO" "$DB" "$PID" "$HANDLE" || {
  rm -rf "$RESTART_TMP"
  fail "restart process B reported failures"
}
rm -rf "$RESTART_TMP"

echo "PASS: test-async-detached.sh"
