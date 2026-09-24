#!/bin/sh
# scripts/test-c-output.sh -- output-contract driver.
#
# Compiles tests/c/output_contracts.c against cbits/native_bindings.c
# (standalone, no provider needed) and runs it. Asserts the native
# output contract: size-query/short/exact with canaries, null vs
# zero capacity, checked conversions, partial batches, multi-handle
# transactions, and nested IV writeback.
#
# Usage (from haskoki/):
#   scripts/test-c-output.sh
# Run inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-c-output.sh
#
# Exit status: 0 iff the contracts pass.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

TMPD="${TMPDIR:-/tmp}/haskoki-output"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  -Icbits \
  -o "$TMPD/output_contracts" tests/c/output_contracts.c cbits/native_bindings.c \
  || fail "output_contracts.c did not compile"
echo "contracts compiled: $TMPD/output_contracts (bindings: cbits/native_bindings.c)"

"$TMPD/output_contracts" || fail "output_contracts reported failures"

echo "PASS: test-c-output.sh (output contracts + canaries + writeback)"
