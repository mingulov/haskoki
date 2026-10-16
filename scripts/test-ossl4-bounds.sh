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
# The foreign-library stanza must never define the test-hook macro:
# it is the shipped module's configuration.
awk '/^foreign-library haskoki/{f=1;next} /^[^ \t-]/{f=0} f' haskoki.cabal \
  | grep -q 'HSK_OSSL4_TEST_HOOKS' \
  && fail "foreign-library stanza defines HSK_OSSL4_TEST_HOOKS"
echo "STATIC: foreign-library stanza does not define HSK_OSSL4_TEST_HOOKS"
# Cabal does not recompile a C source when only cc-options change, so
# a stale object could hide a define that reached the shipped module.
# Delete the foreign library's C objects: the check below then always
# inspects objects built with the current flags.
find dist-newstyle -path '*/f/haskoki/build/haskoki/haskoki-tmp/cbits/*.o' -delete \
  2>/dev/null || true
# shellcheck disable=SC2086
cabal build $EXTRA_LIB_DIRS foreign-library:haskoki \
  || fail "foreign-library build failed"

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
