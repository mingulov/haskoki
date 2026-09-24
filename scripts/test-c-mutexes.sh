#!/bin/sh
# scripts/test-c-mutexes.sh -- callback-lock canary driver.
#
# Compiles tests/c/mutexes.c (standalone, no provider needed) against
# the pinned 3.2 headers and runs it. Asserts callback
# create/use/destroy counts including partial-init cleanup paths.
#
# Usage (from haskoki/):
#   scripts/test-c-mutexes.sh
# Run inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-c-mutexes.sh
#
# Exit status: 0 iff the canary passes.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

TMPD="${TMPDIR:-/tmp}/haskoki-mutexes"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  -Ispec/vendor \
  -o "$TMPD/mutexes" tests/c/mutexes.c -lpthread \
  || fail "mutexes.c did not compile"
echo "canary compiled: $TMPD/mutexes (headers: spec/vendor)"

"$TMPD/mutexes" || fail "mutexes reported failures"

echo "PASS: test-c-mutexes.sh (callback counts + partial cleanup)"
