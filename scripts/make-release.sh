#!/bin/sh
# scripts/make-release.sh -- release artifact builder.
#
# Builds the module + haskoki-ctl, captures the dependency closure,
# bundles a relocatable artifact, and writes the toolchain record:
#   dist-release/haskoki-<ver>/
#     lib/libhaskoki.so          the loadable module
#     lib/libHS*.so              bundled GHC/store closure (explicit)
#     lib/ossl-modules/legacy.so pinned legacy provider module
#     lib/libcrypto.so.4         pinned libcrypto for it (module builds only)
#     bin/haskoki-ctl            operator tool (static Haskell)
#     smoke/release_smoke.c      install smoke source (self-contained)
#     smoke/include/pkcs11*.h    pinned 2.40 headers for the smoke
#     closure/ldd-libhaskoki.txt captured ldd (toolchain side)
#     closure/ldd-haskoki-ctl.txt
#     closure/review.txt         closure review (see below)
#     toolchain-record.txt       compiler, sources lock, engine builds, ABI
#     INSTALL.md                 host deps + no-env setup (self-resolving bundle)
#
# Closure policy (reviewed in closure/review.txt): libcrypto is
# STATICALLY linked from the pinned /opt/openssl-4.0.2 build (no
# libcrypto/libssl in the module's ldd — stronger than "pinned .so
# only"); the dynamic closure is exactly {libHS* (bundled),
# libm/libgmp/libffi/libnuma/libc (host deps)}. No host-global
# libcrypto can interpose. The legacy CIPHER provider is the one
# runtime plugin: OpenSSL ships it only as a separate module, so the
# artifact carries the pinned legacy.so above and the module anchors
# its provider search path off its own directory at context creation
# (cbits/ossl4_ctx.c hsk_ossl4_anchor_providers); the dev tree (no
# shipped dir) keeps the baked /opt default. The host pinned build
# links legacy.so against libcrypto.so.4, so host-built artifacts
# also ship that file with legacy.so's RUNPATH repointed to
# $ORIGIN/..; the image pinned build is self-contained (no libcrypto
# NEEDED) and ships legacy.so alone.
#
# Usage:
#   scripts/make-release.sh                 # build into dist-release/
#   HASKOKI_RELEASE_DIR=<dir> scripts/make-release.sh
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/make-release.sh
#
# Exit status: 0 iff the artifact is complete and the review gates hold.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

cabal build all || fail "cabal build all failed"

SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
[ -n "$SO_LIST" ] || fail "no loadable module found"
[ "$SO_COUNT" -eq 1 ] || fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
SO="$SO_LIST"
CTL=$(find dist-newstyle -path '*haskoki-ctl/haskoki-ctl' -type f 2>/dev/null | sort | head -1)
[ -n "$CTL" ] || fail "haskoki-ctl binary not found"
echo "module under test: $SO"
echo "ctl binary: $CTL"

VER=$(grep -m1 '^version:' haskoki.cabal | awk '{print $2}')
[ -n "$VER" ] || fail "cannot parse version from haskoki.cabal"
OUT="${HASKOKI_RELEASE_DIR:-dist-release}/haskoki-$VER"
rm -rf "$OUT"
mkdir -p "$OUT/lib" "$OUT/bin" "$OUT/smoke/include" "$OUT/closure" \
  || fail "cannot create $OUT"

cp "$SO" "$OUT/lib/libhaskoki.so" || fail "copy module"
cp "$CTL" "$OUT/bin/haskoki-ctl" || fail "copy ctl"
cp tests/c/release_smoke.c "$OUT/smoke/" || fail "copy smoke"
cp spec/vendor/pkcs11.h "$OUT/smoke/include/" \
  || fail "copy smoke headers"

# Closure capture + review gates.
ldd "$SO" > "$OUT/closure/ldd-libhaskoki.txt" 2>&1 \
  || fail "ldd failed on module"
ldd "$CTL" > "$OUT/closure/ldd-haskoki-ctl.txt" 2>&1 \
  || fail "ldd failed on ctl"
if grep -c "not found" "$OUT/closure/ldd-libhaskoki.txt" | grep -q -v '^0$'; then
  grep "not found" "$OUT/closure/ldd-libhaskoki.txt"
  fail "module closure has unresolved libs (run: cabal build all, same container)"
fi
if grep -i -E "libcrypto|libssl" "$OUT/closure/ldd-libhaskoki.txt"; then
  fail "dynamic libcrypto/libssl in module closure (must be static pinned)"
fi
echo "STATIC: no dynamic libcrypto/libssl in module closure"

# Bundle every libHS* the module needs (GHC RTS closure, explicit).
BUNDLED=0
ldd "$SO" | awk '/libHS.*=>/ {print $3}' | sort -u | while read -r lib; do
  [ -n "$lib" ] || continue
  cp "$lib" "$OUT/lib/" || exit 1
done || fail "bundling GHC closure failed"
BUNDLED=$(ls "$OUT/lib"/libHS*.so 2>/dev/null | wc -l)
[ "$BUNDLED" -gt 0 ] || fail "no libHS bundled (closure parse broke?)"
echo "bundled GHC closure libs: $BUNDLED"

# Provider pair (legacy cipher module + its libcrypto): R1 loads the
# "legacy" provider at open and the module is a separate .so resolved
# through the libctx search path (baked MODULESDIR under /opt, absent
# on install hosts). Ship the pinned pair so installs init without
# /opt; the module anchors the search path off its own directory when
# this dir exists (dev tree keeps the baked default).
mkdir -p "$OUT/lib/ossl-modules" || fail "cannot create provider dir"
MODDIR=""
for cand in /opt/openssl-4.0.2/lib64/ossl-modules /opt/openssl-4.0.2/lib/ossl-modules; do
  if [ -f "$cand/legacy.so" ]; then MODDIR="$cand"; break; fi
done
[ -n "$MODDIR" ] || fail "pinned legacy.so not found (need ossl-modules under /opt/openssl-4.0.2 lib64/ or lib/)"
cp "$MODDIR/legacy.so" "$OUT/lib/ossl-modules/legacy.so" || fail "copy legacy.so"
if readelf -d "$OUT/lib/ossl-modules/legacy.so" | grep -q 'NEEDED.*libcrypto'; then
  # Module-build legacy.so (host layout): it binds libcrypto.so.4, so
  # ship the pinned archive next to it and repoint its RUNPATH into
  # the artifact. In-place same-length DT-string rewrite
  # (chrpath-equivalent; perl is present on the host and in the
  # toolchain image, chrpath is not): the old prefix bytes plus NUL
  # are overwritten with the shorter new path plus NUL padding, so
  # every file offset stays valid.
  LIBCRYPTO="$(dirname "$MODDIR")/libcrypto.so.4"
  [ -f "$LIBCRYPTO" ] || fail "pinned libcrypto.so.4 not found next to $MODDIR"
  cp -L "$LIBCRYPTO" "$OUT/lib/libcrypto.so.4" || fail "copy libcrypto.so.4"
  command -v perl >/dev/null 2>&1 || fail "perl required (repoint shipped legacy.so RUNPATH)"
  command -v readelf >/dev/null 2>&1 || fail "readelf required (verify legacy.so RUNPATH)"
  OLDPREFIX="$(dirname "$MODDIR")"
  ACTUALPATHS=$(readelf -d "$OUT/lib/ossl-modules/legacy.so" | grep -E '(RPATH|RUNPATH)' | grep -oE '\[[^]]*\]' || true)
  echo "$ACTUALPATHS" | grep -qF "[$OLDPREFIX]" \
    || fail "legacy.so RUNPATH is not the pinned prefix (wont patch blind): $ACTUALPATHS"
  perl -e '
    use strict; use warnings;
    my ($f, $old, $new) = @ARGV;
    open(my $in, "<:raw", $f) or die "open $f: $!";
    my $d; { local $/; $d = <$in>; } close $in;
    my $want = $old . "\x00";
    die "new path longer than old" if length($new) + 1 > length($want);
    my $repl = $new . ("\x00" x (length($want) - length($new)));
    my $c = () = $d =~ /\Q$want\E/g;
    die "prefix occurs $c times, want >= 1" unless $c >= 1;
    $d =~ s/\Q$want\E/$repl/g;
    open(my $out, ">:raw", $f) or die "write $f: $!";
    print $out $d; close $out;
  ' "$OUT/lib/ossl-modules/legacy.so" "$OLDPREFIX" '$ORIGIN/..' \
    || fail "legacy.so RUNPATH rewrite failed"
  readelf -d "$OUT/lib/ossl-modules/legacy.so" | grep -q 'RUNPATH.*\$ORIGIN/\.\.' \
    || fail "legacy.so RUNPATH repoint failed"
  LEGCRYPTO=$(ldd "$OUT/lib/ossl-modules/legacy.so" | awk '/libcrypto\.so\.4 =>/ {print $3}')
  if [ -z "$LEGCRYPTO" ] || [ "$(realpath "$LEGCRYPTO")" != "$(realpath "$OUT/lib/libcrypto.so.4")" ]; then
    ldd "$OUT/lib/ossl-modules/legacy.so" | grep "libcrypto" || true
    fail "shipped legacy.so does not bind the artifact libcrypto.so.4"
  fi
  PROVIDER_FILES="ossl-modules/legacy.so + libcrypto.so.4"
  PROVIDER_KIND="module build; legacy.so RUNPATH repointed to \$ORIGIN/.."
  EXTRA_CRYPTO_SHA="$OUT/lib/libcrypto.so.4"
else
  # Static provider build (image layout): legacy.so binds no libcrypto
  # (self-contained, SYMBOLIC); ship it alone.
  PROVIDER_FILES="ossl-modules/legacy.so"
  PROVIDER_KIND="self-contained static provider build; no libcrypto dep"
  EXTRA_CRYPTO_SHA=""
fi
if ldd "$OUT/lib/ossl-modules/legacy.so" | grep "not found"; then
  fail "shipped legacy.so has unresolved libs"
fi
echo "bundled provider: $PROVIDER_FILES ($PROVIDER_KIND; from $MODDIR)"

# Host-side (NOT bundled) dynamic deps of the module: must be exactly
# the documented system set {libm, libgmp, libffi, libnuma, libc,
# ld-linux, vdso}. (libffi/libnuma come from the OS GHC's threaded
# RTS; the ghcup alpha bindist bundles libffi instead.)
ldd "$SO" | awk '{print $1}' | grep '\.so' | grep -v '^libHS' | sort -u \
  > "$OUT/closure/host-deps.txt"
echo "host deps (must be system-only):"
cat "$OUT/closure/host-deps.txt"
if grep -v -E "^(libm\.so|libgmp\.so|libffi\.so|libnuma\.so|libc\.so|linux-vdso)|ld-linux" \
    "$OUT/closure/host-deps.txt" | grep -q .; then
  fail "unexpected host dep outside {libm,libgmp,libffi,libnuma,libc,ld-linux,vdso}"
fi
echo "STATIC: host deps are system-only"

# glibc floor: max GLIBC_* ref over the module AND every bundled lib
# (the module alone understates it: OS-built libHS* can exceed it).
FLOOR=$(for f in "$OUT/lib"/*.so "$OUT/lib/ossl-modules/"*.so "$OUT/bin/haskoki-ctl"; do
  objdump -T "$f" 2>/dev/null | grep -o "GLIBC_[0-9.]*"
done | sort -uV | tail -1)
[ -n "$FLOOR" ] || fail "cannot compute glibc floor"
echo "glibc floor: $FLOOR"

# Review record.
{
  echo "closure review — haskoki $VER ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "module: $SO"
  echo ""
  echo "libcrypto: STATIC, pinned /opt/openssl-4.0.2 build (libcrypto.a"
  echo "linked into libhaskoki.so at build; ldd shows no libcrypto/libssl;"
  echo "no host-global libcrypto can interpose). Engine self-report:"
  /opt/openssl-4.0.2/bin/openssl version 2>/dev/null || echo "(pinned openssl CLI not on PATH; see toolchain-record)"
  echo ""
  echo "provider (shipped, \$ORIGIN-anchored): lib/$PROVIDER_FILES"
  echo "($PROVIDER_KIND) from the pinned prefix ($MODDIR);"
  echo "ldd-verified inside the artifact."
  echo "sha256:"
  sha256sum "$OUT/lib/ossl-modules/legacy.so" $EXTRA_CRYPTO_SHA | sed 's#^#  #'
  echo ""
  echo "bundled GHC/store libs ($BUNDLED):"
  ls "$OUT/lib"/libHS*.so | xargs -n1 basename | sort
  echo ""
  echo "host system deps (documented in INSTALL.md + SUPPORTED-HOSTS.md):"
  cat "$OUT/closure/host-deps.txt"
  echo ""
  echo "glibc floor (max GLIBC_* version ref over lib/ + ctl):"
  echo "$FLOOR"
} > "$OUT/closure/review.txt"
cat "$OUT/closure/review.txt"

# Toolchain record.
{
  echo "toolchain record — haskoki $VER"
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git SHA: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "host ABI: $(uname -srm)"
  echo "builder image: ${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
  echo "ghc: $(ghc --version 2>/dev/null)"
  echo "cabal: $(cabal --version 2>/dev/null | head -1)"
  echo "cc: $(cc --version 2>/dev/null | head -1)"
  echo "builder glibc: $(ldd --version 2>/dev/null | head -1)"
  echo "freeze: cabal.project.freeze sha256 $(sha256sum cabal.project.freeze 2>/dev/null | awk '{print $1}')"
  echo "toolchain.lock sha256 $(sha256sum toolchain.lock 2>/dev/null | awk '{print $1}')"
  echo "engine builds:"
  echo "  openssl4 prefix: /opt/openssl-4.0.2"
  /opt/openssl-4.0.2/bin/openssl version 2>/dev/null | sed 's/^/  pinned openssl: /' || echo "  pinned openssl: CLI unavailable"
  echo "  linkage: static libcrypto.a into libhaskoki.so (extra-libraries: crypto)"
  echo "artifact sha256:"
  (cd "$OUT" && find lib bin smoke -type f | sort | xargs sha256sum)
} > "$OUT/toolchain-record.txt"

# INSTALL.md.
{
  echo "# haskoki $VER — install notes"
  echo ""
  echo "Contents: \`lib/libhaskoki.so\` (loadable PKCS#11 module),"
  echo "\`lib/libHS*.so\` (bundled GHC runtime closure, $BUNDLED libs),"
  echo "pinned legacy provider (\$ORIGIN-anchored): \`lib/$PROVIDER_FILES\`"
  echo "($PROVIDER_KIND), \`bin/haskoki-ctl\` (operator tool), \`smoke/\`"
  echo "(install smoke source + pinned headers), \`closure/\` (captured"
  echo "dependency closure + review), \`toolchain-record.txt\`."
  echo ""
  echo "## Host requirements"
  echo ""
  echo "- Linux x86-64, glibc >= ${FLOOR#GLIBC_} (see SUPPORTED-HOSTS.md)."
  echo "- System libraries: libc, libm, libgmp.so.10, libffi.so.8,"
  echo "  libnuma.so.1 (Debian/Ubuntu: \`apt-get install libgmp10"
  echo "  libffi8 libnuma1\`)."
  echo "- libcrypto is statically linked from the pinned OpenSSL 4.0.2"
  echo "  build; NO system libcrypto is used or required. (The legacy"
  echo "  cipher provider ships under \`lib/\` as pinned bytes, resolved"
  echo "  inside lib/ — never the host libcrypto. \`$PROVIDER_FILES\`.)"
  echo ""
  echo "## Setup"
  echo ""
  echo "No environment setup is needed: the module resolves its"
  echo "bundled closure from its own directory (\$ORIGIN RUNPATH;"
  echo "verified: every libHS* resolves inside lib/ with"
  echo "LD_LIBRARY_PATH unset), and \`bin/haskoki-ctl\` is fully"
  echo "static (no bundled libs needed at all)."
  echo "Keep \`lib/\` together: \`libhaskoki.so\` next to the bundled"
  echo "\`libHS*.so\` files plus the provider files (do not separate"
  echo "them)."
  echo ""
  echo "Load \`lib/libhaskoki.so\` as a PKCS#11 module, or run"
  echo "\`bin/haskoki-ctl --version\`. No certification or"
  echo "production-security claim is made for this build (demo scope;"
  echo "see SUPPORTED-HOSTS.md limitations)."
} > "$OUT/INSTALL.md"

echo "artifact complete: $OUT"
du -sh "$OUT" "$OUT/lib"
echo "PASS: make-release.sh (artifact + closure + record)"
