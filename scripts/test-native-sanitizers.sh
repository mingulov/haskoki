#!/bin/sh
# scripts/test-native-sanitizers.sh: targeted GCC ASan/UBSan qualification of
# the ossl4 shim boundary. Compiles cbits/ossl4_ctx.c into the C harness
# tests/c/ossl4_sanitize.c in two source configurations (hooks / prod),
# instrumented: an instrumented harness, not the shipped object. libcrypto
# and GHC are not instrumented. Unsupported instrumentation is an OPEN gate
# (exit 3), never a pass.
#   scripts/test-native-sanitizers.sh
#   docker run --rm -e HASKOKI_IMAGE_ID=<id> -v "$PWD:/work" -w /work \
#     haskoki-dev:ghc-9.10.3 scripts/test-native-sanitizers.sh
#
# Exit: 0 gate pass, 1 gate fail, 3 gate open (probe could not establish
# that the sanitizers work here). A receipt is written in every case:
# $HASKOKI_SAN_ART/receipt.json, schema haskoki-native-sanitizer-receipt/1.
set -u
HERE=$(dirname "$0"); cd "$HERE/.." || exit 1
ART=${HASKOKI_SAN_ART:-${TMPDIR:-/tmp}/haskoki-native-sanitizers}
rm -rf "$ART"; mkdir -p "$ART/bin" "$ART/logs" || exit 1
CC=${CC:-gcc}; OSSL=/opt/openssl-4.0.2
COMMON="-std=c11 -Wall -Wextra -Werror -pthread -Icbits -I$OSSL/include"
SAN="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
PLAIN="-O1 -g"
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:detect_stack_use_after_return=1:strict_string_checks=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

COMMON_CASES="prod-digest-cycle prod-env-cycle prod-dh-kat prod-ecdh prod-xdh prod-aead"
SEAM_CASES="seam-bn-named seam-bn-explicit seam-derive-fail-shrink-ecdh seam-derive-fail-grow-ecdh seam-derive-ok-shrink-ecdh seam-derive-ok-grow-ecdh seam-derive-fail-shrink-xdh seam-derive-fail-grow-xdh seam-derive-ok-shrink-xdh seam-derive-ok-grow-xdh seam-derive-fail-shrink-dh seam-derive-fail-grow-dh seam-derive-ok-shrink-dh seam-derive-ok-grow-dh"
HOOKS_TRACK_CASES="live-1000 credit-gone address-reuse copy-fault adoption-alloc adoption-load final-fault canary-selftest $SEAM_CASES $COMMON_CASES"
# Track mode checks free counts, extent and canaries through the tracking
# allocator; plain mode leaves the real allocation boundaries to ASan, so
# the seam and copy-fault buffers run in both. address-reuse and
# canary-selftest need the tracker itself; the harness refuses them in
# plain mode (exit 2).
HOOKS_PLAIN_CASES="live-1000 credit-gone copy-fault adoption-alloc adoption-load final-fault $SEAM_CASES $COMMON_CASES"

CASES_TSV="$ART/cases.tsv"; NEG_TSV="$ART/negative.tsv"; OVH_TSV="$ART/overhead.tsv"
: > "$CASES_TSV"; : > "$NEG_TSV"; : > "$OVH_TSV"
LIBCRYPTO=""; GATE=fail; OPEN_REASON=""

json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r\t'; }
sha_of() { if [ -f "$1" ]; then sha256sum "$1" | cut -d' ' -f1; else printf ''; fi; }

write_receipt() {
  _gate=$1; _reason=$2
  # The commit and cleanliness are measured here when git can read the
  # checkout (sha_source "measured"). A worktree mounted into a container
  # has no usable git directory: then the commit comes from HASKOKI_SAN_SHA
  # (exactly 40 lowercase hex) and the cleanliness from HASKOKI_SAN_DIRTY
  # (true|false), both supplied by the caller (sha_source "caller").
  # Without either the receipt says unknown / dirty.
  if _sha=$(git -c safe.directory="$PWD" rev-parse HEAD 2>/dev/null); then
    _src=measured
    if [ -z "$(git -c safe.directory="$PWD" status --porcelain -- cbits tests/c scripts/test-native-sanitizers.sh 2>/dev/null)" ]; then
      _dirty=false
    else
      _dirty=true
    fi
  else
    _src=caller
    if printf '%s' "${HASKOKI_SAN_SHA:-}" | grep -Eqx '[0-9a-f]{40}'; then
      _sha=$HASKOKI_SAN_SHA
    else
      _sha=unknown; _src=none
    fi
    case ${HASKOKI_SAN_DIRTY:-} in
      false) _dirty=false ;;
      *) _dirty=true ;;
    esac
  fi
  _img=${HASKOKI_IMAGE_ID:-host (no container)}
  _cc=$($CC --version 2>/dev/null | head -1)
  _rt=$($CC -print-file-name=libasan.so 2>/dev/null)
  {
    printf '{\n'
    printf '  "schema": "haskoki-native-sanitizer-receipt/1",\n'
    printf '  "sha": "%s",\n  "sha_source": "%s",\n  "dirty": %s,\n' "$(json_str "$_sha")" "$_src" "$_dirty"
    printf '  "image_id": "%s",\n  "compiler": "%s",\n' "$(json_str "$_img")" "$(json_str "$_cc")"
    printf '  "asan_runtime": "%s",\n' "$(json_str "$_rt")"
    printf '  "libcrypto": {"path": "%s", "sha256": "%s"},\n' "$(json_str "$LIBCRYPTO")" "$(sha_of "$LIBCRYPTO")"
    printf '  "sources": {"cbits/ossl4_ctx.c": "%s", "cbits/ossl4_ctx.h": "%s", "tests/c/ossl4_sanitize.c": "%s", "scripts/test-native-sanitizers.sh": "%s"},\n' \
      "$(sha_of cbits/ossl4_ctx.c)" "$(sha_of cbits/ossl4_ctx.h)" "$(sha_of tests/c/ossl4_sanitize.c)" "$(sha_of scripts/test-native-sanitizers.sh)"
    printf '  "variants": [\n'
    _first=1
    for _v in "san-hooks|hooks|$SAN -DHSK_OSSL4_TEST_HOOKS" "san-prod|prod|$SAN" \
              "plain-hooks|hooks|$PLAIN -DHSK_OSSL4_TEST_HOOKS" "plain-prod|prod|$PLAIN"; do
      _n=${_v%%|*}; _r=${_v#*|}; _c=${_r%%|*}; _f=${_r#*|}
      if [ "$_c" = hooks ]; then _cfg="hooks: HSK_OSSL4_TEST_HOOKS"; else _cfg="prod: production source configuration"; fi
      [ $_first = 1 ] || printf ',\n'; _first=0
      printf '    {"name": "%s", "shim_variant": "instrumented harness, not the shipped object", "config": "%s", "flags": "%s %s"}' \
        "$_n" "$_cfg" "$(json_str "$COMMON")" "$(json_str "$_f")"
    done
    printf '\n  ],\n'
    printf '  "asan_options": "%s",\n  "ubsan_options": "%s",\n' "$(json_str "$ASAN_OPTIONS")" "$(json_str "$UBSAN_OPTIONS")"
    printf '  "cases": ['
    _first=1
    while IFS='	' read -r _b _m _c _e _vd; do
      [ -n "$_b" ] || continue
      [ $_first = 1 ] || printf ','; _first=0
      printf '\n    {"binary": "%s", "mem": "%s", "case": "%s", "exit": %s, "verdict": "%s"}' "$_b" "$_m" "$_c" "$_e" "$_vd"
    done < "$CASES_TSV"
    printf '\n  ],\n  "negative_controls": ['
    _first=1
    while IFS='	' read -r _b _m _c _mk _e _vd; do
      [ -n "$_b" ] || continue
      [ $_first = 1 ] || printf ','; _first=0
      printf '\n    {"binary": "%s", "mem": "%s", "case": "%s", "marker": "%s", "exit": %s, "verdict": "%s"}' \
        "$_b" "$_m" "$_c" "$(json_str "$_mk")" "$_e" "$_vd"
    done < "$NEG_TSV"
    printf '\n  ],\n  "overhead_ns": {'
    _first=1
    while IFS='	' read -r _b _t; do
      [ -n "$_b" ] || continue
      [ $_first = 1 ] || printf ', '; _first=0
      printf '"%s": %s' "$_b" "$_t"
    done < "$OVH_TSV"
    printf '},\n'
    printf '  "overhead_env": "%s; %s cpus; 6 common cases, plain mem, one run each; image %s",\n' \
      "$(json_str "$(uname -sr)")" "$(nproc 2>/dev/null || echo '?')" "$(json_str "$_img")"
    printf '  "gate": "%s",\n  "open_reason": "%s",\n' "$_gate" "$(json_str "$_reason")"
    printf '  "limits": "libcrypto not instrumented; GHC/RTS not instrumented; harness compiles the shim source, the shipped .so is checked separately by test-ossl4-bounds.sh"\n'
    printf '}\n'
  } > "$ART/receipt.json"
}

fail() {
  write_receipt fail "$1"
  echo "FAIL: $1"
  echo "SANITIZER-GATE: FAIL reason=$1"
  exit 1
}

open_gate() {
  write_receipt open "$1"
  echo "SANITIZER-GATE: OPEN reason=$1"
  exit 3
}

# --- probes: any failure in 1-3 is an open gate, never a pass --------------
for d in "$OSSL/lib" "$OSSL/lib64"; do
  if [ -f "$d/libcrypto.a" ]; then LIBCRYPTO="$d/libcrypto.a"; break; fi
done
[ -n "$LIBCRYPTO" ] || open_gate libcrypto-absent

cat > "$ART/probe-ok.c" <<'EOP'
int main(void) { return 0; }
EOP
cat > "$ART/probe-leak.c" <<'EOP'
#include <stdlib.h>
void *volatile sink;
int main(void) { sink = malloc(32); sink = 0; return 0; }
EOP

# shellcheck disable=SC2086
$CC $SAN -o "$ART/bin/probe-ok" "$ART/probe-ok.c" > "$ART/logs/probe-ok-compile.log" 2>&1 \
  || open_gate probe-compile
"$ART/bin/probe-ok" > "$ART/logs/probe-ok-run.log" 2>&1 || open_gate probe-run

# shellcheck disable=SC2086
$CC $SAN -o "$ART/bin/probe-leak" "$ART/probe-leak.c" > "$ART/logs/probe-leak-compile.log" 2>&1 \
  || open_gate probe-compile
"$ART/bin/probe-leak" > "$ART/logs/probe-leak-run.log" 2>&1
LEAK_RC=$?
if grep -q "LeakSanitizer has encountered a fatal error" "$ART/logs/probe-leak-run.log" \
   || grep -q "LeakSanitizer does not work under ptrace" "$ART/logs/probe-leak-run.log"; then
  open_gate lsan-unavailable
fi
[ "$LEAK_RC" -ne 0 ] || fail "leak control silent"
grep -q "detected memory leaks" "$ART/logs/probe-leak-run.log" || open_gate lsan-unavailable

# --- builds ------------------------------------------------------------------
build() { # name flags
  # shellcheck disable=SC2086
  $CC $COMMON $2 -o "$ART/bin/$1" cbits/ossl4_ctx.c tests/c/ossl4_sanitize.c "$LIBCRYPTO" -ldl \
    > "$ART/logs/build-$1.log" 2>&1 || fail "build $1"
}
build san-hooks "$SAN -DHSK_OSSL4_TEST_HOOKS"
build san-prod "$SAN"
build plain-hooks "$PLAIN -DHSK_OSSL4_TEST_HOOKS"
build plain-prod "$PLAIN"

# --- case lists must match what each binary reports ----------------------------
check_list() { # bin expected-list
  "$ART/bin/$1" --list 2>/dev/null | sort > "$ART/logs/list-$1.actual"
  printf '%s\n' $2 | sort > "$ART/logs/list-$1.expected"
  cmp -s "$ART/logs/list-$1.actual" "$ART/logs/list-$1.expected" || fail "case list incomplete"
}
check_list san-hooks "$HOOKS_TRACK_CASES"
check_list plain-hooks "$HOOKS_TRACK_CASES"
check_list san-prod "$COMMON_CASES"
check_list plain-prod "$COMMON_CASES"

# --- runs ----------------------------------------------------------------------
run_case() { # bin mem case
  _log="$ART/logs/$1.$2.$3.log"
  "$ART/bin/$1" --mem "$2" --case "$3" > "$_log" 2>&1
  _rc=$?
  if [ $_rc -eq 0 ] && grep -q "^CASE $3 PASS " "$_log"; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$_rc" pass >> "$CASES_TSV"
  else
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$_rc" fail >> "$CASES_TSV"
    fail "case $1 $2 $3 (exit $_rc, see logs/$1.$2.$3.log)"
  fi
}

expect_fail() { # bin mem case marker(ERE) [exit] [extra harness args]
  _log="$ART/logs/neg.$1.$2.$3.log"
  _want=${5:-}
  # shellcheck disable=SC2086
  "$ART/bin/$1" --mem "$2" --case "$3" ${6:-} > "$_log" 2>&1
  _rc=$?
  _ok=1
  if [ -n "$_want" ]; then [ "$_rc" -eq "$_want" ] || _ok=0; else [ "$_rc" -ne 0 ] || _ok=0; fi
  grep -Eq -- "$4" "$_log" || _ok=0
  if [ $_ok = 1 ]; then _v=pass; else _v=fail; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$_rc" "$_v" >> "$NEG_TSV"
  [ $_ok = 1 ] || fail "negative control $3 did not fail as required (exit $_rc, marker '$4')"
}

for c in $HOOKS_TRACK_CASES; do run_case san-hooks track "$c"; done
for c in $HOOKS_PLAIN_CASES; do run_case san-hooks plain "$c"; done
for c in $COMMON_CASES; do run_case san-prod track "$c"; run_case san-prod plain "$c"; done
for c in $HOOKS_TRACK_CASES; do run_case plain-hooks track "$c"; done
for c in $COMMON_CASES; do run_case plain-prod track "$c"; done
for c in $HOOKS_PLAIN_CASES; do run_case plain-hooks plain "$c"; done
for c in $COMMON_CASES; do run_case plain-prod plain "$c"; done

# --- negative controls: each must fail when its condition is present -------------
expect_fail san-prod plain neg-double-free "attempting double-free"
# Production destruction is not suppressed: a handle freed twice reaches
# ASan (the shim reads the handle while releasing it, so the report is a
# use-after-free or a double free).
expect_fail san-prod plain neg-handle-double-free "heap-use-after-free|attempting double-free"
expect_fail san-prod plain neg-env-double-free "heap-use-after-free|attempting double-free"
expect_fail san-prod plain neg-heap-overflow "heap-buffer-overflow"
expect_fail san-prod plain neg-ubsan "runtime error:"
expect_fail san-hooks track exit-gate "unacknowledged double-free" 70
expect_fail san-hooks track seam-bn-named "seam-not-reached" "" --no-arm

# --- overhead (wall time of the 6 common cases, plain memory) ---------------------
for b in san-hooks san-prod plain-hooks plain-prod; do
  t0=$(date +%s%N)
  for c in $COMMON_CASES; do "$ART/bin/$b" --mem plain --case "$c" > /dev/null 2>&1; done
  t1=$(date +%s%N)
  printf '%s\t%s\n' "$b" "$((t1 - t0))" >> "$OVH_TSV"
done

GATE=pass
write_receipt pass ""
echo "PASS: test-native-sanitizers.sh (gate pass)"
exit 0
