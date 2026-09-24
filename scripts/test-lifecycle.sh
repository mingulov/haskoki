#!/bin/sh
# scripts/test-lifecycle.sh -- stale-handle lifecycle driver.
#
# Two probes, one verdict:
#   1. tests/c/lifecycle.c (deterministic, single-threaded): builds
#      against the pinned 3.2 header family and pins the fail-fast
#      contract through the REAL entries (C_WaitForSlotEvent +
#      HASKOKI_Control answer CKR_CRYPTOKI_NOT_INITIALIZED outside an
#      init interval; re-init serves again).
#   2. tools/lifecycle-probe (subprocess-isolated injection): opens,
#      closes, re-opens, then USES the stale handle; every stale use
#      must answer NOT_INITIALIZED (a deRef-after-free would crash or
#      succeed cross-generation instead).
#
# Usage:
#   scripts/test-lifecycle.sh            # both probes (must PASS)
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-lifecycle.sh
#
# Exit status: 0 iff both probes pass.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

cabal build all --enable-tests || fail "cabal build all failed"

# 0. Independence guard: the C probe must never consume
#    provider-generated orderings; it uses pinned vendor headers only.
if grep -rn "abi_generated\|abi_stubs\|abi-inventory" tests/c/lifecycle.c 2>/dev/null; then
  fail "probe independence violated (see grep hits above)"
fi
echo "STATIC: lifecycle probe does not include provider-generated artifacts"

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

TMPD="${TMPDIR:-/tmp}/haskoki-lifecycle"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

# 2. Deterministic fail-fast pins through the real entries.
BIN="$TMPD/lifecycle"
cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  -Ispec/vendor \
  -o "$BIN" tests/c/lifecycle.c -ldl -lpthread \
  || fail "lifecycle probe did not compile"
echo "probe compiled: $BIN (headers: spec/vendor)"

"$BIN" "$SO" || fail "lifecycle probe reported failures"

# 3. Stale-handle injection (subprocess-isolated: a probe crash must
#    not take this driver down — the exit code carries the verdict).
PROBE=$(find dist-newstyle -name 'lifecycle-probe' -type f 2>/dev/null | sort | head -1)
if [ -z "$PROBE" ]; then
  fail "lifecycle-probe binary not found (cabal build all should have built it)"
fi
echo "injection probe: $PROBE"
OUT="$TMPD/injection.out"
if timeout -s KILL 120 "$PROBE" > "$OUT" 2>&1; then
  grep -q "STALE-USE-RESULT all-not-initialized" "$OUT" \
    || fail "injection probe exited 0 without the clean marker (see $OUT)"
else
  RC=$?
  echo "--- injection output (rc=$RC) ---"
  cat "$OUT"
  echo "--- end injection output ---"
  fail "injection probe failed with rc=$RC (crash or wrong-code on stale use)"
fi

echo "PASS: test-lifecycle.sh (fail-fast pins + stale-handle injection)"
