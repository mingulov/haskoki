#!/bin/sh
# scripts/test-control-events.sh — native control/slot-event proof.
#
# Builds the shared module in-container (`cabal build all`, incremental
# over the bind-mounted dist-newstyle), then compiles
# tests/c/control_events.c as an independent non-Haskell executable
# and runs it against the built .so. Also proves the new C entry TU
# is -Wall -Wextra -Werror clean via a standalone syntax check.
#
# The in-container build is load-bearing, not convenience: the module
# links Haskell dependencies whose shared objects live in the
# container's ephemeral cabal store, so only a module built in THIS
# container is guaranteed dlopenable here (its RUNPATH names this
# container's store).
#
#   Run (from haskoki/):
#     docker run --rm -v "$PWD:/work" -w /work \
#       haskoki-dev:ghc-9.10.3 scripts/test-control-events.sh
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

# New-C strictness gate: the control entry TU + proof must be
# -Wall -Wextra -Werror clean as standalone translation units.
cc -std=c11 -O2 -g -Wall -Wextra -Werror -fsyntax-only \
  -Icbits cbits/control_entry.c \
  || fail "control_entry.c not -Wall -Wextra -Werror clean"
echo "control_entry.c strict-clean: ok"

BIN="${TMPDIR:-/tmp}/haskoki-control-events"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor \
  -o "$BIN" tests/c/control_events.c -ldl -pthread \
  || fail "C proof harness did not compile"
echo "harness compiled: $BIN"

# Keep the tree clean: the native instance resolves HASKOKI_TRACE at
# init (the trace-dest override); point it at scratch. Also asserts
# the override path end to end (the proof's control calls emit).
export HASKOKI_TRACE="${TMPDIR:-/tmp}/haskoki-proof-trace.jsonl"
rm -f "$HASKOKI_TRACE"

"$BIN" "$SO" || fail "C proof harness reported failures"
[ -s "$HASKOKI_TRACE" ] || fail "expected trace lines at $HASKOKI_TRACE"
echo "native trace override: ok ($HASKOKI_TRACE)"

echo "PASS: test-control-events.sh"
