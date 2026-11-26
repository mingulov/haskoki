#!/bin/sh
# scripts/test-usdt-bench.sh -- dormant-probe overhead bench.
#
# Compares the off vs unattached (+usdt, no consumer) builds through
# the real .so with a warmed native single-capability workload
# (tests/c/usdt_bench.c: AES-256-CBC-PAD one-shot encrypt+decrypt
# round-trips, decrypt verified every iteration):
#   1. builds flib:haskoki --flags=+usdt, stages it aside, and proves
#      the flag took effect (readelf exact-manifest gate);
#   2. rebuilds flib:haskoki with default flags, stages it aside,
#      and proves it carries zero notes (--expect-off gate);
#   3. compiles the driver once and runs both legs warmed;
#   4. asserts both legs exit 0 (every measured op was real) and the
#      unattached leg runs within 2x of the off leg.
# The 2x bound is deliberately loose: it catches catastrophic
# regressions (an attached consumer left on, per-op sleeps,
# quadratic emission) without flaking on shared CI runners. The
# per-op microseconds of both legs are reported for the record.
# Prints PASS: test-usdt-bench.sh on success.
#
# Usage:
#   scripts/test-usdt-bench.sh
#
# Env:
#   HASKOKI_USDT_BENCH_ITERS  timed iterations per leg (default 300;
#                             bogus values fail fast before the build).
#
# Prerequisites (self-provisioned via apt when missing, failing
# loudly): sys/sdt.h (systemtap-sdt-dev) and python3 for the
# readelf gates. Runs as root in its containers.
set -u

fail() {
  echo "FAIL: $1"
  exit 1
}

ITERS="${HASKOKI_USDT_BENCH_ITERS:-300}"
case "$ITERS" in
  '' | *[!0-9]* | 0*) fail "bogus HASKOKI_USDT_BENCH_ITERS: $ITERS" ;;
esac
if [ "$ITERS" -lt 10 ] || [ "$ITERS" -gt 100000 ]; then
  fail "HASKOKI_USDT_BENCH_ITERS out of range 10..100000: $ITERS"
fi

# sdt.h + python3 (readelf gates below) come from the toolchain
# image; a stale image self-provisions via apt and fails loudly.
need_apt=0
if ! echo '#include <sys/sdt.h>' | cc -E -x c - -o /dev/null >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v python3 >/dev/null 2>&1; then
  need_apt=1
fi
if [ "$need_apt" = "1" ]; then
  echo "provisioning systemtap-sdt-dev + python3 via apt"
  apt-get update || fail "apt-get update failed"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemtap-sdt-dev python3 || fail "apt-get install failed"
  echo '#include <sys/sdt.h>' | cc -E -x c - -o /dev/null >/dev/null 2>&1 \
    || fail "sys/sdt.h still missing after install"
  command -v python3 >/dev/null 2>&1 || fail "python3 still missing after install"
fi

cabal build flib:haskoki --flags=+usdt || fail "cabal build flib:haskoki --flags=+usdt failed"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
[ -n "$SO_LIST" ] || fail "no loadable module found"
[ "$SO_COUNT" -eq 1 ] || fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
echo "on-build module: $SO_LIST"

TMPD="${TMPDIR:-/tmp}/haskoki-usdt-bench"
mkdir -p "$TMPD" || fail "cannot create $TMPD"
cp "$SO_LIST" "$TMPD/libhaskoki-on.so" || fail "cannot stage on-build module"

python3 scripts/check-usdt-probes.py --so "$TMPD/libhaskoki-on.so" \
  || fail "on-build module probe manifest mismatch"

cabal build flib:haskoki || fail "cabal build flib:haskoki (default flags) failed"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
[ -n "$SO_LIST" ] || fail "no loadable module found after off rebuild"
[ "$SO_COUNT" -eq 1 ] || fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
echo "off-build module: $SO_LIST"
cp "$SO_LIST" "$TMPD/libhaskoki-off.so" || fail "cannot stage off-build module"

python3 scripts/check-usdt-probes.py --so "$TMPD/libhaskoki-off.so" --expect-off \
  || fail "off-build module carries probe notes"

if ! cc -std=c11 -O2 -g -Wall -Wextra -Werror \
    -Ispec/vendor \
    -o "$TMPD/usdt_bench" tests/c/usdt_bench.c -ldl -lpthread; then
  fail "usdt_bench.c did not compile"
fi
echo "bench driver compiled: $TMPD/usdt_bench"

OFF_OUT=$("$TMPD/usdt_bench" "$TMPD/libhaskoki-off.so" "$ITERS" 2>"$TMPD/off.err") \
  || { cat "$TMPD/off.err" >&2; fail "off leg failed"; }
ON_OUT=$("$TMPD/usdt_bench" "$TMPD/libhaskoki-on.so" "$ITERS" 2>"$TMPD/on.err") \
  || { cat "$TMPD/on.err" >&2; fail "unattached leg failed"; }

OFF_NS=$(printf '%s' "$OFF_OUT" | sed -n 's/^BENCH-NS:\([0-9]*\) ITERS:.*/\1/p')
ON_NS=$(printf '%s' "$ON_OUT" | sed -n 's/^BENCH-NS:\([0-9]*\) ITERS:.*/\1/p')
[ -n "$OFF_NS" ] && [ -n "$ON_NS" ] \
  || fail "unparsable bench output: off=[$OFF_OUT] on=[$ON_OUT]"

echo "off leg:        ${OFF_NS}ns / ${ITERS} iters"
echo "unattached leg: ${ON_NS}ns / ${ITERS} iters"
awk -v off="$OFF_NS" -v on="$ON_NS" -v n="$ITERS" 'BEGIN {
  printf "per-op: off %.2fus, unattached %.2fus, ratio %.3f\n",
    off / n / 1000, on / n / 1000, on / off
}'

if [ "$ON_NS" -ge $((OFF_NS * 2)) ]; then
  fail "unattached leg slower than 2x off (${ON_NS}ns vs ${OFF_NS}ns)"
fi

echo "PASS: test-usdt-bench.sh (off ${OFF_NS}ns, unattached ${ON_NS}ns, $ITERS iters)"
