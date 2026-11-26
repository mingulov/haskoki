#!/bin/sh
# scripts/test-usdt-live.sh -- USDT live-capture publish gate.
#
# Builds flib:haskoki --flags=+usdt, proves the probe manifest
# (readelf exact-manifest gate), compiles the capture workload
# (tests/c/usdt_live.c: fixture matrix + edge scenarios with
# PHASE markers), runs it under the committed GDB recipe
# (tests/gdb/usdt_cap.txt, unprivileged, no BPF/kernel
# requirements), and asserts every typed record with
# scripts/usdt-live-check.py (field-exact pk records, counts,
# silence legs, op-id correlation across threads, global
# pairing/tag/range invariants). Prints PASS: test-usdt-live.sh
# on success.
#
# The driver must reach PHASE:done (any functional failure fails
# the recipe before analysis); the analyzer fails on any record
# deviation. OPENSSL_MODULES inherits from the environment when
# the prefix needs it (stale local prefixes); fresh prefixes and
# release containers need none.
#
# Usage:
#   scripts/test-usdt-live.sh
#
# Prerequisites (self-provisioned via apt when missing, failing
# loudly): sys/sdt.h (systemtap-sdt-dev), python3, gdb. Runs as
# root in its containers.
set -u

fail() {
  echo "FAIL: $1"
  exit 1
}

REPO="$PWD"
[ -f "$REPO/haskoki.cabal" ] || fail "run from the repository root"

# sdt.h + python3 + gdb come from the toolchain image; a stale
# image self-provisions via apt and fails loudly.
need_apt=0
if ! echo '#include <sys/sdt.h>' | cc -E -x c - -o /dev/null >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v python3 >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v gdb >/dev/null 2>&1; then
  need_apt=1
fi
if [ "$need_apt" = "1" ]; then
  echo "provisioning systemtap-sdt-dev + python3 + gdb via apt"
  apt-get update || fail "apt-get update failed"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemtap-sdt-dev python3 gdb || fail "apt-get install failed"
  echo '#include <sys/sdt.h>' | cc -E -x c - -o /dev/null >/dev/null 2>&1 \
    || fail "sys/sdt.h still missing after install"
  command -v python3 >/dev/null 2>&1 || fail "python3 still missing after install"
  command -v gdb >/dev/null 2>&1 || fail "gdb still missing after install"
fi

cabal build flib:haskoki --flags=+usdt || fail "cabal build flib:haskoki --flags=+usdt failed"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
[ -n "$SO_LIST" ] || fail "no loadable module found"
[ "$SO_COUNT" -eq 1 ] || fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
echo "on-build module: $SO_LIST"

TMPD="${TMPDIR:-/tmp}/haskoki-usdt-live"
rm -rf "$TMPD" || fail "cannot clear $TMPD"
mkdir -p "$TMPD" || fail "cannot create $TMPD"
cp "$SO_LIST" "$TMPD/libhaskoki-on.so" || fail "cannot stage on-build module"
cp tests/gdb/usdt_cap.txt "$TMPD/" || fail "cannot stage gdb recipe"

python3 scripts/check-usdt-probes.py --so "$TMPD/libhaskoki-on.so" \
  || fail "on-build module probe manifest mismatch"

if ! cc -std=c11 -O2 -g -Wall -Wextra -Werror \
    -Ispec/vendor \
    -o "$TMPD/usdt_live" tests/c/usdt_live.c -ldl -lpthread; then
  fail "usdt_live.c did not compile"
fi
echo "live driver compiled: $TMPD/usdt_live"

cd "$TMPD" || fail "cannot enter $TMPD"
gdb -batch -x ./usdt_cap.txt >cap.out 2>&1
GDB_RC=$?
[ "$GDB_RC" -eq 0 ] || { tail -n 30 cap.out >&2; fail "gdb exited $GDB_RC"; }
grep -q "^PHASE:done$" cap.out \
  || { grep -E "^(FAIL|PHASE)" cap.out >&2; fail "driver did not reach PHASE:done"; }
grep -q "^NEW " cap.out || fail "capture holds no pk records"

python3 "$REPO/scripts/usdt-live-check.py" "$TMPD/cap.out" \
  || fail "capture analysis failed"

echo "PASS: test-usdt-live.sh (live capture analyzed clean)"
