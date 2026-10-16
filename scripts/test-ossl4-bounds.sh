#!/bin/sh
# scripts/test-ossl4-bounds.sh — ossl4 FFI regression proof (audit findings 1-3).
#
# Compiles tests/c/ossl4_bounds.c as an independent non-Haskell
# executable and runs it against the built shared module. The driver
# resolves the hsk_ossl4_* entry points directly and pins the success
# + error contracts of the findings-hardened helpers (AEAD GCM/CCM
# round-trips and error legs, DH KAT + error legs).
#
#   Run (from haskoki/):
#     scripts/test-ossl4-bounds.sh
#   (in the pinned toolchain image via bind mount, like the other
#   drivers:
#     docker run --rm -v "$PWD:/work" -w /work \
#       haskoki-dev:ghc-9.10.3 scripts/test-ossl4-bounds.sh)
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

# The driver needs only the shared module: build just the foreign
# library, not the world. Host checkouts stage the pinned OpenSSL 4
# prefix under lib64/ (the image uses lib/); pass it through when
# present so :libcrypto.a resolves in both places.
EXTRA_LIB_DIRS=""
if [ -d /opt/openssl-4.0.2/lib64 ]; then
  EXTRA_LIB_DIRS="--extra-lib-dirs=/opt/openssl-4.0.2/lib64"
fi
# The test-hook macro belongs to the main library stanza only. Anywhere
# else in haskoki.cabal (the foreign-library stanza, a common stanza it
# imports, another component) or in any cabal.project* file it could
# reach the shipped module. Comment lines are ignored.
awk '/^library[ \t]*$/{lib=1;next} /^[^ \t-]/{lib=0} !lib && !/^[ \t]*--/' haskoki.cabal \
  | grep -q 'HSK_OSSL4_TEST_HOOKS' \
  && fail "HSK_OSSL4_TEST_HOOKS appears in haskoki.cabal outside the library stanza"
for f in cabal.project*; do
  [ -f "$f" ] || continue
  grep -v '^[ \t]*--' "$f" | grep -q 'HSK_OSSL4_TEST_HOOKS' \
    && fail "HSK_OSSL4_TEST_HOOKS appears in $f"
done
echo "STATIC: HSK_OSSL4_TEST_HOOKS is defined only in the library stanza"
# Cabal does not recompile a C source when only cc-options change, and
# with no monitored change it skips the component entirely ("Up to
# date"), so deleting the objects alone leaves the old module in place.
# Delete the foreign library's C objects and its build cache, then
# require the shim object to exist again: the module inspected below is
# always linked from objects built with the current flags.
FLIB_OBJ_GLOB='*/f/haskoki/build/haskoki/haskoki-tmp/cbits/*.o'
find dist-newstyle -path "$FLIB_OBJ_GLOB" -delete 2>/dev/null || true
find dist-newstyle -path '*/f/haskoki/cache/build' -delete 2>/dev/null || true
# shellcheck disable=SC2086
cabal build $EXTRA_LIB_DIRS foreign-library:haskoki \
  || fail "foreign-library build failed"
FLIB_OBJ=$(find dist-newstyle -path '*/f/haskoki/build/haskoki/haskoki-tmp/cbits/ossl4_ctx.o' 2>/dev/null)
[ -n "$FLIB_OBJ" ] \
  || fail "foreign-library build did not recreate cbits/ossl4_ctx.o (stale module)"
echo "REBUILT: $FLIB_OBJ"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
if [ -z "$SO_LIST" ]; then
  fail "no loadable module found (foreign-library build produced none)"
fi
if [ "$SO_COUNT" -ne 1 ]; then
  echo "found candidates:"
  echo "$SO_LIST"
  fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
fi
SO="$SO_LIST"
echo "module under test: $SO"
# Byte-order collation: sort, comm and the committed inventory agree.
export LC_ALL=C
SYMS=tests/c/ossl4_test_symbols.txt
[ -s "$SYMS" ] || fail "missing $SYMS"
TMPO="${TMPDIR:-/tmp}/haskoki-ossl4-variants"; mkdir -p "$TMPO" || fail "cannot create $TMPO"
CFL="-std=c11 -Wall -Wextra -Werror -pthread -I/opt/openssl-4.0.2/include"
cc $CFL -c -o "$TMPO/prod.o" cbits/ossl4_ctx.c || fail "production-config shim did not compile"
cc $CFL -DHSK_OSSL4_TEST_HOOKS -c -o "$TMPO/hooks.o" cbits/ossl4_ctx.c || fail "test-config shim did not compile"
globals() { nm --defined-only -g "$1" | awk 'NF==3 && $2 ~ /^[TDBR]$/ {print $3}' | sort -u; }
globals "$TMPO/prod.o" > "$TMPO/prod.syms"; globals "$TMPO/hooks.o" > "$TMPO/hooks.syms"
comm -13 "$TMPO/prod.syms" "$TMPO/hooks.syms" > "$TMPO/only-hooks.syms"
# The production configuration defines no test or seam symbol at all,
# local ones included (the live-sets and seams are static).
PROD_TEST=$(nm "$TMPO/prod.o" | grep -E 'hsk_test_|hsk_seam|hsk_ossl4_test_' || true)
[ -z "$PROD_TEST" ] || { echo "$PROD_TEST"; fail "production-config shim defines test or seam symbols"; }
echo "STATIC: production-config shim defines no test or seam symbol"
diff -u "$SYMS" "$TMPO/only-hooks.syms" || fail "test-only symbol inventory drifted (update $SYMS deliberately)"
echo "STATIC: test-only symbol inventory matches ($(wc -l < "$SYMS") symbols)"
nm -D --defined-only "$SO" | awk 'NF==3{print $3}' | sort -u > "$TMPO/so.syms"
grep -qx hsk_ossl4_dh_derive "$TMPO/so.syms" || fail "nm sanity: hsk_ossl4_dh_derive not exported"
LEAK=$(comm -12 "$SYMS" "$TMPO/so.syms")
[ -z "$LEAK" ] || { echo "$LEAK"; fail "shipped module exports test-hook symbols"; }
echo "STATIC: shipped module exports no test-hook symbol"

BIN="${TMPDIR:-/tmp}/haskoki-ossl4-bounds"
cc -std=c11 -O2 -g -Wall -Wextra -Werror -o "$BIN" tests/c/ossl4_bounds.c -ldl \
  || fail "C proof harness did not compile"
echo "harness compiled: $BIN"

"$BIN" "$SO" || fail "C proof harness reported failures"

echo "PASS: test-ossl4-bounds.sh"
