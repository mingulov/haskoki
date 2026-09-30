#!/bin/sh
# scripts/test-consumers.sh -- direct-load native C consumer scenarios.
#
# Compiles each tests/c/consumer_*.c against the pinned 3.2 header family
# (3.2 header; newer-API surface, never provider-generated types) and runs
# it against the built shared module:
#   consumer_discovery  per-interface discovery (GetInterfaceList/GetInterface
#                       for 3.2/3.1/3.0 + legacy GetFunctionList), versioned-
#                       table isolation, mechanism/info queries
#   consumer_roundtrip  REAL round-trips through the legacy
#                       C_GetFunctionList table: digest (one-shot/multipart/
#                       size-query edges), sessions, objects (create/get/
#                       copy/find/destroy), login/logout incl lockout,
#                       keygen (AES/EC pair; RSA honestly refused),
#                       sign/verify (ECDSA+HMAC, one-shot/multipart),
#                       encrypt/decrypt (AES-CBC-PAD/CBC/ECB, ARIA-CBC,
#                       one-shot/multipart), wrap/unwrap, HKDF derive,
#                       GenerateRandom + SeedRandom (seed mixes)
#
# Usage:
#   scripts/test-consumers.sh             # build scenarios, run all (must PASS)
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-consumers.sh
#
# Exit status: 0 iff every consumer scenario passes.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

[ -f tests/c/message_routed.c ] || fail "message consumer missing"
[ -f tests/c/async_routed.c ] || fail "async consumer missing"
SCEN_LIST=$(
  for scen in tests/c/consumer_*.c tests/c/message_routed.c tests/c/async_routed.c; do
    [ -f "$scen" ] && printf '%s\n' "$scen"
  done | LC_ALL=C sort -u
)
[ -n "$SCEN_LIST" ] || fail "consumer scenario list empty"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/message_routed.c')" -eq 1 ] \
  || fail "message consumer must occur exactly once"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/async_routed.c')" -eq 1 ] \
  || fail "async consumer must occur exactly once"
for scen in $SCEN_LIST; do
  if grep -nE 'abi_generated|abi_stubs|abi-inventory' "$scen"; then
    fail "consumer independence violated: $scen"
  fi
done
echo "STATIC: consumer scenarios do not include provider-generated artifacts"

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

# 2. Display the complete consumer scenario list.
echo "consumer scenarios:"
echo "$SCEN_LIST"

TMPD="${TMPDIR:-/tmp}/haskoki-consumers"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

run_scenario() {
  # $1 = source path
  base=$(basename "$1" .c)
  BIN="$TMPD/$base"
  cc -std=c11 -O2 -g -Wall -Wextra -Werror \
    -Ispec/vendor \
    -o "$BIN" "$1" -ldl -lpthread \
    || fail "$base did not compile"
  echo "scenario compiled: $BIN (headers: spec/vendor)"
  "$BIN" "$SO" || fail "$base reported failures"
}

if [ -n "${1:-}" ]; then
  fail "usage: scripts/test-consumers.sh"
fi

for scen in $SCEN_LIST; do
  run_scenario "$scen"
done

echo "PASS: test-consumers.sh (direct-load consumer scenarios)"
