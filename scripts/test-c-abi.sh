#!/bin/sh
# scripts/test-c-abi.sh -- layout/prototype probe driver.
#
# Compiles each tests/c/layout_*.c against the single pinned header
# (never provider-generated types) plus cbits/abi_probe.c from source,
# then runs all four probes against the built shared module:
#   layout_240  2.40 scalars/layouts/prototypes + legacy table (A01/A02)
#   layout_300  3.0 ditto + ("PKCS 11", 3.0) selection (A01/A02)
#   layout_310  3.1 ditto on the 3.0 layout + distinct 3.1 instance (A02)
#   layout_320  3.2 ditto + interface matrix + dual-table isolation (A02)
#
# Usage:
#   scripts/test-c-abi.sh             # build probes, run all four (must PASS)
#   scripts/test-c-abi.sh --negative  # probe-sensitivity check: mutate ONE
#     scratch expectation and prove the probe catches it (must be CAUGHT).
#     Nothing under tests/ is modified; the mutation lives in $TMPDIR.
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-c-abi.sh
#
# Exit status: 0 iff every probe passes (or, with --negative, iff the
# mutated probe is caught at compile time or run time).
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

cabal build all || fail "cabal build all failed"

# 0. Independence guard: probes must never consume provider-generated
#    orderings; their expectations are hardcoded and verified here.
if grep -rn "abi_generated\|abi_stubs\|abi-inventory" tests/c/ 2>/dev/null; then
  fail "probe independence violated (see grep hits above)"
fi
echo "STATIC: probes do not include provider-generated artifacts"

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

# 2. The 3.x discovery symbols must be exported for dlsym (A01).
for sym in C_GetInterfaceList C_GetInterface; do
  if ! nm -D --defined-only "$SO" 2>/dev/null | grep -q " T $sym$"; then
    fail "exported symbol missing from $SO: $sym"
  fi
done
echo "STATIC: C_GetInterfaceList/C_GetInterface exported"

TMPD="${TMPDIR:-/tmp}/haskoki-c-probes"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

compile_probe() {
  # $1 = tag (240/300/310/320), $2 = source, $3 = output, $4 = extra cflags
  # shellcheck disable=SC2086
  cc -std=c11 -O2 -g -Wall -Wextra -Werror \
    -Ispec/vendor -Icbits $4 \
    -o "$3" "$2" cbits/abi_probe.c -ldl
}

run_probe() {
  # $1 = tag
  # layout_300 asserts the DSA typo/canonical alias pair, whose typo
  # spelling the header gates behind PKCS11_DEPRECATED; every other
  # probe uses only always-visible names.
  EXTRA=""
  [ "$1" = "300" ] && EXTRA="-DPKCS11_DEPRECATED=1"
  BIN="$TMPD/layout_$1"
  compile_probe "$1" "tests/c/layout_$1.c" "$BIN" "$EXTRA" \
    || fail "layout_$1 did not compile"
  echo "probe compiled: $BIN (headers: spec/vendor/pkcs11.h)"
  "$BIN" "$SO" || fail "layout_$1 reported failures"
}

if [ "${1:-}" = "--negative" ]; then
  # Probe-sensitivity (TDD negative case): corrupt ONE hardcoded ordinal
  # in a scratch copy. C_GetSlotList is 2.40 ordinal 4 (offset 40); claim
  # ordinal 5 (offset 48) and demand the probe catch the lie.
  MUT_SRC="$TMPD/layout_240_mut.c"
  MUT_BIN="$TMPD/layout_240_mut"
  cp tests/c/layout_240.c "$MUT_SRC" || fail "cannot stage mutation"
  if ! grep -q "CHECK_FN(CK_FUNCTION_LIST, 4, C_GetSlotList);" "$MUT_SRC"; then
    fail "mutation anchor missing (probe source changed?)"
  fi
  sed -i 's/CHECK_FN(CK_FUNCTION_LIST, 4, C_GetSlotList);/CHECK_FN(CK_FUNCTION_LIST, 5, C_GetSlotList);/' "$MUT_SRC"
  grep -q "CHECK_FN(CK_FUNCTION_LIST, 5, C_GetSlotList);" "$MUT_SRC" \
    || fail "mutation did not apply"
  echo "NEGATIVE: mutated C_GetSlotList ordinal 4 -> 5 in scratch copy"
  if compile_probe "240" "$MUT_SRC" "$MUT_BIN" "" \
      2>"$TMPD/mut.log"; then
    if "$MUT_BIN" "$SO" >/dev/null 2>&1; then
      fail "NEGATIVE: mutated probe compiled AND passed (insensitive!)"
    else
      echo "PASS (negative): mutation caught at run time"
    fi
  else
    echo "PASS (negative): mutation caught at compile time:"
    grep -m2 -i "error" "$TMPD/mut.log" | head -n 2
  fi
  # The real probe must still pass afterwards (mutation was scratch-only).
  run_probe "240"
  echo "PASS: test-c-abi.sh --negative (sensitivity proven)"
  exit 0
fi

if [ -n "${1:-}" ]; then
  fail "usage: scripts/test-c-abi.sh [--negative]"
fi

run_probe "240"
run_probe "300"
run_probe "310"
run_probe "320"

echo "PASS: test-c-abi.sh (layout/prototype probes + isolation)"
