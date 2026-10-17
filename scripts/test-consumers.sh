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
#   consumer_rts_caps   capability-count legs against the built module:
#                       GHCRTS=-N4 and unsafe GHCRTS=-A8m must both
#                       yield one capability with the host surviving
#   consumer_rts_race   concurrent first-call race against the built
#                       module: 8 barrier-released threads make their
#                       first native call (haskoki_async_open) at once,
#                       in each of 20 fresh processes; every call must
#                       return a context, and a post-init fork child
#                       must refuse the native surface
#   consumer_rts_midfork
#                       deterministic mid-init fork probe against the
#                       built module: interposed hs_init_ghc parks the
#                       winning thread inside init while a mid-init
#                       fork child must refuse every surface and a
#                       loser thread must keep waiting (explicit
#                       wiring below, like rts_caps_probe: it needs
#                       the RTS headers and -rdynamic, so the generic
#                       scenario build cannot take it)
#   rts_caps_probe      same GHCRTS legs against rts_bootstrap.c
#                       compiled from source with its test-only
#                       capability-count accessor (explicit wiring
#                       below; not a consumer_*.c scenario)
#
# Usage:
#   scripts/test-consumers.sh             # build scenarios, run all (must PASS)
#
# Matrix legs (V4b behavioral qualification; each a no-op when unset,
# and every bogus value fails fast before the build):
#   HASKOKI_QUAL_ONLY=<basename>  run only the scenario whose basename
#                                 (minus .c) matches exactly, e.g.
#                                 consumer_multithread, async_routed,
#                                 rts_caps_probe, or consumer_rts_midfork
#                                 (each probe skips the scenarios then)
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
# consumer_rts_midfork is excluded from the generic list: it needs
# the RTS headers and -rdynamic, so the explicit block below builds
# it the way rts_caps_probe is built.
SCEN_LIST=$(
  for scen in tests/c/consumer_*.c tests/c/message_routed.c tests/c/async_routed.c tests/c/notifications_routed.c tests/c/consumer_certificates.c; do
    [ -f "$scen" ] && printf '%s\n' "$scen"
  done | LC_ALL=C sort -u | grep -vx 'tests/c/consumer_rts_midfork.c'
)
[ -n "$SCEN_LIST" ] || fail "consumer scenario list empty"
RUN_PROBE=1
RUN_MIDFORK=1
if [ "${HASKOKI_QUAL_ONLY:-}" = "rts_caps_probe" ]; then
  SCEN_LIST=""
  RUN_MIDFORK=0
  echo "scenario filter: rts_caps_probe (RTS bootstrap probe only)"
elif [ "${HASKOKI_QUAL_ONLY:-}" = "consumer_rts_midfork" ]; then
  SCEN_LIST=""
  RUN_PROBE=0
  echo "scenario filter: consumer_rts_midfork (RTS mid-init fork probe only)"
elif [ -n "${HASKOKI_QUAL_ONLY:-}" ]; then
  # Scenario filter: exact basename match (minus .c), validated
  # before the build so a bogus hint fails fast without a toolchain.
  # Both probes are skipped under a scenario filter.
  RUN_PROBE=0
  RUN_MIDFORK=0
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

# RTS include discovery, shared by the two probes below (each needs
# -I on the threaded RTS include dir).
RTS_INCDIR=""
if [ "$RUN_PROBE" = "1" ] || [ "$RUN_MIDFORK" = "1" ]; then
  command -v ghc >/dev/null 2>&1 || fail "ghc not found (the RTS probes need ghc --print-libdir)"
  GHC_LIBDIR=$(ghc --print-libdir) || fail "ghc --print-libdir failed"
  RTS_ARCHDIR=""
  RTS_ARCH_COUNT=0
  for d in "$GHC_LIBDIR"/x86_64-linux-ghc-*; do
    [ -d "$d" ] || continue
    RTS_ARCHDIR="$d"
    RTS_ARCH_COUNT=$((RTS_ARCH_COUNT + 1))
  done
  [ "$RTS_ARCH_COUNT" -eq 1 ] || fail "expected exactly one GHC arch dir under $GHC_LIBDIR, found $RTS_ARCH_COUNT"
  RTS_INC_COUNT=0
  for d in "$RTS_ARCHDIR"/rts-*/include; do
    [ -d "$d" ] || continue
    RTS_INCDIR="$d"
    RTS_INC_COUNT=$((RTS_INC_COUNT + 1))
  done
  [ "$RTS_INC_COUNT" -eq 1 ] || fail "expected exactly one RTS include dir under $RTS_ARCHDIR, found $RTS_INC_COUNT"
fi

# RTS bootstrap probe: compiles cbits/rts_bootstrap.c from source with
# the test-only capability-count accessor (the shipped module never
# defines the macro) and drives its init code under hostile GHCRTS
# values. Needs the threaded RTS link; skipped under a scenario
# filter unless the filter names this probe.
if [ "$RUN_PROBE" = "1" ]; then
  [ -f tests/c/rts_caps_probe.c ] || fail "RTS bootstrap probe missing"
  PROBE_BIN="$TMPD/rts_caps_probe"
  # Linked with ghc -no-hs-main (a C main): only ghc knows the
  # RTS/base library closure a plain cc link cannot satisfy. The
  # startup under test is still rts_bootstrap.c's own init call.
  if ! ghc -no-hs-main -threaded \
      -I"$RTS_INCDIR" \
      -optc-DHSK_OSSL4_TEST_HOOKS \
      -optc-std=c11 -optc-O2 -optc-g -optc-Wall -optc-Wextra -optc-Werror \
      -optl-Wl,-rpath,"$RTS_ARCHDIR" \
      -odir "$TMPD" -hidir "$TMPD" \
      -o "$PROBE_BIN" tests/c/rts_caps_probe.c cbits/rts_bootstrap.c \
      -lpthread -ldl; then
    echo "FAIL: rts_caps_probe did not compile"
    FAILURES="$FAILURES rts_caps_probe(compile)"
  else
    echo "scenario compiled: $PROBE_BIN (bootstrap: cbits/rts_bootstrap.c)"
    ec=0; "$PROBE_BIN" || ec=$?
    echo "child exit: rts_caps_probe $ec"
    if [ "$ec" -ne 0 ]; then
      echo "FAIL: rts_caps_probe reported failures"
      FAILURES="$FAILURES rts_caps_probe(exit $ec)"
    fi
  fi
fi

# RTS mid-init fork probe: interposes hs_init_ghc (the binary exports
# its own, hence -rdynamic) to park the winning thread inside init
# while a mid-init fork child must refuse every surface and a loser
# thread must keep waiting. A plain cc link takes it (no RTS link:
# the real init is reached through the dlopen'd module); skipped
# under a scenario filter unless the filter names this probe.
if [ "$RUN_MIDFORK" = "1" ]; then
  [ -f tests/c/consumer_rts_midfork.c ] || fail "RTS mid-init fork probe missing"
  MIDFORK_BIN="$TMPD/consumer_rts_midfork"
  # shellcheck disable=SC2086
  if ! cc -std=c11 -O2 -g -Wall -Wextra -Werror \
      -Ispec/vendor \
      -I"$RTS_INCDIR" \
      -rdynamic \
      $WIDTH_FLAGS \
      -o "$MIDFORK_BIN" tests/c/consumer_rts_midfork.c -ldl -lpthread; then
    echo "FAIL: consumer_rts_midfork did not compile"
    FAILURES="$FAILURES consumer_rts_midfork(compile)"
  else
    echo "scenario compiled: $MIDFORK_BIN (headers: spec/vendor + RTS)"
    ec=0; "$MIDFORK_BIN" "$SO" || ec=$?
    echo "child exit: consumer_rts_midfork $ec"
    if [ "$ec" -ne 0 ]; then
      echo "FAIL: consumer_rts_midfork reported failures"
      FAILURES="$FAILURES consumer_rts_midfork(exit $ec)"
    fi
  fi
fi

[ -z "$FAILURES" ] || fail "consumer failures:$FAILURES"

echo "PASS: test-consumers.sh (direct-load consumer scenarios)"
