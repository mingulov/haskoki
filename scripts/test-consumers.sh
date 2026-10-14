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
#   consumer_multithread
#                       barrier-start distinct-session SHA-256 load:
#                       per-worker unique inputs, one-shot vs multipart
#                       full-byte agreement, size-query liveness, an
#                       independent sha256("abc") oracle, cross-worker
#                       distinctness, and session conservation
#
# Usage:
#   scripts/test-consumers.sh             # build scenarios, run all (must PASS)
#
# Matrix legs (V4b behavioral qualification; each a no-op when unset,
# and every bogus value fails fast before the build):
#   HASKOKI_QUAL_ONLY=<basename>  run only the scenario whose basename
#                                 (minus .c) matches exactly, e.g.
#                                 consumer_multithread or async_routed
#   HASKOKI_WIDTH_LEG=64          compile every scenario with
#                                 -DHASKOKI_WIDTH_LEG=64 (the 64-bit cell)
# Probe legs pass through untouched (the probes read them):
# HASKOKI_MT_PIN_ROTATE, HASKOKI_MT_AGING, HASKOKI_MT_MUTEX,
# HASKOKI_MT_FAIR, HASKOKI_MT_HINT_STRICT, HASKOKI_ASYNC_REROUTE,
# HASKOKI_ASYNC_PARALLEL_SEED, HASKOKI_MT_N, HASKOKI_MT_ITERS.
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

# Width leg: strict (only 64 exists), validated before the build so
# a bogus hint fails fast without a toolchain.
WIDTH_FLAGS=""
if [ -n "${HASKOKI_WIDTH_LEG:-}" ]; then
  if [ "$HASKOKI_WIDTH_LEG" = "64" ]; then
    WIDTH_FLAGS="-DHASKOKI_WIDTH_LEG=64"
  else
    fail "HASKOKI_WIDTH_LEG must be 64 (got: $HASKOKI_WIDTH_LEG)"
  fi
fi

[ -f tests/c/message_routed.c ] || fail "message consumer missing"
[ -f tests/c/async_routed.c ] || fail "async consumer missing"
[ -f tests/c/notifications_routed.c ] || fail "notifications consumer missing"
[ -f tests/c/consumer_certificates.c ] || fail "certificates consumer missing"
[ -f tests/c/consumer_notifications_poll.c ] || fail "notifications polling consumer missing"
[ -f tests/c/consumer_multithread.c ] || fail "multithread consumer missing"
SCEN_LIST=$(
  for scen in tests/c/consumer_*.c tests/c/message_routed.c tests/c/async_routed.c tests/c/notifications_routed.c tests/c/consumer_certificates.c; do
    [ -f "$scen" ] && printf '%s\n' "$scen"
  done | LC_ALL=C sort -u
)
[ -n "$SCEN_LIST" ] || fail "consumer scenario list empty"
if [ -n "${HASKOKI_QUAL_ONLY:-}" ]; then
  # Scenario filter: exact basename match (minus .c), validated
  # before the build so a bogus hint fails fast without a toolchain.
  QUAL_HIT=""
  for scen in $SCEN_LIST; do
    if [ "$(basename "$scen" .c)" = "$HASKOKI_QUAL_ONLY" ]; then
      QUAL_HIT="$scen"
    fi
  done
  [ -n "$QUAL_HIT" ] || fail "HASKOKI_QUAL_ONLY matched no scenario: $HASKOKI_QUAL_ONLY"
  SCEN_LIST="$QUAL_HIT"
  echo "scenario filter: $HASKOKI_QUAL_ONLY ($SCEN_LIST)"
else
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/message_routed.c')" -eq 1 ] \
    || fail "message consumer must occur exactly once"
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/async_routed.c')" -eq 1 ] \
    || fail "async consumer must occur exactly once"
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/notifications_routed.c')" -eq 1 ] \
    || fail "notifications consumer must occur exactly once"
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/consumer_certificates.c')" -eq 1 ] \
    || fail "certificates consumer must occur exactly once"
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/consumer_notifications_poll.c')" -eq 1 ] \
    || fail "notifications polling consumer must occur exactly once"
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/consumer_multithread.c')" -eq 1 ] \
    || fail "multithread consumer must occur exactly once"
fi
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

FAILURES=""

run_scenario() {
  # $1 = source path. Collect-all: a failing scenario is recorded
  # and the rest still run (final-triage F-7: the old fail-fast
  # loop hid later-driver signal behind the first failure).
  # Fail-closed is preserved: any recorded failure exits 1 below.
  base=$(basename "$1" .c)
  BIN="$TMPD/$base"
  # shellcheck disable=SC2086
  if ! cc -std=c11 -O2 -g -Wall -Wextra -Werror \
    -Ispec/vendor \
    $WIDTH_FLAGS \
    -o "$BIN" "$1" -ldl -lpthread; then
    echo "FAIL: $base did not compile"
    FAILURES="$FAILURES $base(compile)"
    return 0
  fi
  echo "scenario compiled: $BIN (headers: spec/vendor)"
  ec=0; "$BIN" "$SO" || ec=$?
  echo "child exit: $base $ec"
  if [ "$ec" -ne 0 ]; then
    echo "FAIL: $base reported failures"
    FAILURES="$FAILURES $base(exit $ec)"
  fi
}

if [ -n "${1:-}" ]; then
  fail "usage: scripts/test-consumers.sh"
fi

for scen in $SCEN_LIST; do
  run_scenario "$scen"
done

[ -z "$FAILURES" ] || fail "consumer failures:$FAILURES"

echo "PASS: test-consumers.sh (direct-load consumer scenarios)"
