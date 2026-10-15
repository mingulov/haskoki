#!/bin/sh
# scripts/test-ownership-matrix.sh -- private-RTS ownership fixture matrix.
#
# Runs the named ownership fixtures (M1-M7 of the concurrency plan)
# under a PRIVATE RTS setting -N1, -N2 and -N4, one receipt per
# (case, RTS), in the pinned toolchain container. Role: qualification
# (scripts/driver-inventory.json): inventoried so the drift rule owns
# it, but outside the 19-step release manifest -- release-evidence.sh
# never runs it; the qualification workflow does.
#
#   Run (from the repo root):
#     docker run --rm --network host -v "$PWD:/work" -w /work \
#       -e HASKOKI_OWN_SHA=<40-hex commit> \
#       haskoki-dev:ghc-9.10.3 scripts/test-ownership-matrix.sh
#
# For each case and each N the driver
#   1. lists the selected tests (`<bin> -p PAT --list-tests`): zero
#      matches, or fewer than the case minimum, is a failure (a
#      pattern that silently matches nothing must never pass);
#   2. runs `<bin> -p PAT -j <n> +RTS -N<n> -s -RTS` and requires the
#      `-s` capability line `using -N<n>` (a binary that ignores the
#      RTS flag fails), exit 0, and passed count == listed count.
#      `-j <n>` is load-bearing: without it tasty raises the
#      capability count to the processor count (measured: -N4 ended
#      as `using -N12`), so the private RTS would be fiction;
#   3. writes <receipts>/<case>.N<n>.json (sha, binary sha256, nproc,
#      rc, listed/passed, using_n, duration_s, counters). The
#      `counters` array carries any `OWNERSHIP-COUNTERS ` stdout lines.
# Collect-all: every cell runs; any failing or missing receipt makes
# the driver exit nonzero. Pending rows (later work packages) are
# reported as PENDING and never counted as passing.
#
# Env (validated BEFORE any build):
#   HASKOKI_OWN_RTS       space/comma list drawn from 1 2 4 (default "1 2 4"; N3 is an error)
#   HASKOKI_OWN_CASE      run one case id from the table (unknown or pending ids are errors)
#   HASKOKI_OWN_SHA       the 40-hex commit under test (default: git rev-parse HEAD)
#   HASKOKI_OWN_RECEIPTS  receipt directory (default dist-qualification/ownership)
#   HASKOKI_OWN_TIMEOUT   per-run timeout seconds (default 1800)
#   HASKOKI_OWN_BIN_DIR   test only: directory holding the three suite binaries
#                         (skips the build; used by the build-free controls)
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

# case|suite|tasty-pattern|min-count|status
# Patterns are tasty 1.5 awk expressions over the test path
# ($1 = suite root, $2 = top group, $3 = subgroup). They must not
# contain `|`. WP07-WP09 rows are appended by those packages as
# `pending` until their fixtures exist.
CASE_TABLE=$(cat <<'TABLE'
m1-native-transfers|model|$2 == "Ownership" && $3 == "native ownership transfers"|1|active
m1-openssl4-engine|engine|$2 == "openssl4 engine"|1|active
m1-acquisition-hooks|engine|$2 == "Acquisition hooks"|1|active
m2-lease-protocol|model|$2 == "Ownership" && $3 == "lease protocol"|1|active
m2-lifetime-gate|model|$2 == "Ownership" && $3 == "lifetime gate"|2|active
m3-handle-registry|model|$2 == "Ownership" && $3 == "handle registry"|1|active
m3-ffi-acquisition|model|$2 == "FFI acquisition"|1|active
m3-async-engine|engine|$2 == "Async engine"|1|active
m4-store-contract|storage|$2 == "store contract"|1|active
m4-multi-session|storage|$2 == "Multi-session store"|1|active
m5-attachment-claims|model|$2 == "Ownership" && $3 == "attachment claims"|1|active
m5-detached-jobs|model|$2 == "Detached jobs"|1|active
m5-scoped-detach-leases|model|$2 == "Scoped detach leases"|1|active
m6-two-contexts-distinct-ids|model|$2 == "Detached jobs" && /two contexts on one store/|1|active
m6-store-wide-counter|model|$2 == "Detached jobs" && /two tokens share the store-wide counter/|1|active
m7-attached-async|model|$2 == "Attached async"|1|active
m7-retirement|model|$2 == "Ownership" && /retire/|1|active
wp07-pending|model|-|0|pending
wp08-pending|model|-|0|pending
wp09-pending|model|-|0|pending
TABLE
)

RTS_LIST=${HASKOKI_OWN_RTS:-"1 2 4"}
RTS_LIST=$(printf '%s' "$RTS_LIST" | tr ',' ' ')
for n in $RTS_LIST; do
  case "$n" in
    1|2|4) ;;
    *) fail "HASKOKI_OWN_RTS must be drawn from 1 2 4 (got: $n)" ;;
  esac
done
[ -n "$RTS_LIST" ] || fail "HASKOKI_OWN_RTS is empty"

ONLY=${HASKOKI_OWN_CASE:-}
if [ -n "$ONLY" ]; then
  row=$(printf '%s\n' "$CASE_TABLE" | awk -F'|' -v c="$ONLY" '$1 == c { print $5 }')
  [ -n "$row" ] || fail "HASKOKI_OWN_CASE is not a case in the table (got: $ONLY)"
  [ "$row" != pending ] || fail "HASKOKI_OWN_CASE $ONLY is pending (no fixture exists yet)"
fi

SHA=${HASKOKI_OWN_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}
case "$SHA" in
  *[!0-9a-f]*|"") fail "HASKOKI_OWN_SHA must be the 40-hex commit under test (got: '$SHA')" ;;
esac
[ "${#SHA}" -eq 40 ] || fail "HASKOKI_OWN_SHA must be 40 hex chars (got ${#SHA})"

TMO=${HASKOKI_OWN_TIMEOUT:-1800}
case "$TMO" in
  ""|*[!0-9]*) fail "HASKOKI_OWN_TIMEOUT must be numeric seconds (got: $TMO)" ;;
esac

OUT=${HASKOKI_OWN_RECEIPTS:-dist-qualification/ownership}
mkdir -p "$OUT" || fail "cannot create $OUT"
rm -f "$OUT"/*.json "$OUT"/*.names "$OUT"/*.out "$OUT"/*.err "$OUT"/index.tsv

# One cabal build of the three suites; binaries are located with
# `cabal list-bin` and hashed into every receipt.
suite_target() {
  case "$1" in
    model) echo haskoki-model-tests ;;
    engine) echo haskoki-engine-tests ;;
    storage) echo haskoki-storage-tests ;;
    *) return 1 ;;
  esac
}
NEEDED=$(printf '%s\n' "$CASE_TABLE" | awk -F'|' -v c="$ONLY" \
  '$5 == "active" && (c == "" || $1 == c) { print $2 }' | sort -u)
TARGETS=""
for s in $NEEDED; do TARGETS="$TARGETS $(suite_target "$s")"; done

if [ -z "${HASKOKI_OWN_BIN_DIR:-}" ]; then
  # shellcheck disable=SC2086
  cabal build $TARGETS --enable-tests || fail "cabal build failed"
fi
bin_of() {
  t=$(suite_target "$1") || return 1
  if [ -n "${HASKOKI_OWN_BIN_DIR:-}" ]; then
    echo "$HASKOKI_OWN_BIN_DIR/$t"
  else
    cabal list-bin -v0 --enable-tests "$t"
  fi
}

json_str() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

NPROC=$(nproc 2>/dev/null || echo 0)
BAD=0
PLANNED=0
TOTAL_OK=0
printf 'case\trts\tlisted\tpassed\trc\tstatus\tduration_s\n' > "$OUT/index.tsv"

while IFS='|' read -r CASE SUITE PAT MIN STATUS; do
  [ -n "$CASE" ] || continue
  if [ "$STATUS" = pending ]; then
    echo "PENDING $CASE (not executed, not counted)"
    continue
  fi
  [ -z "$ONLY" ] || [ "$CASE" = "$ONLY" ] || continue
  BIN=$(bin_of "$SUITE") || fail "no suite for $CASE"
  [ -x "$BIN" ] || fail "test binary missing or not executable for $CASE: $BIN"
  BSHA=$(sha256sum "$BIN" | cut -d' ' -f1)
  NAMES="$OUT/$CASE.names"
  LISTED=0
  LIST_RC=0
  timeout -s KILL "$TMO" "$BIN" -p "$PAT" --list-tests > "$NAMES" 2> "$OUT/$CASE.list.err" || LIST_RC=$?
  rm -f "$OUT/$CASE.list.err"
  if [ "$LIST_RC" -eq 0 ]; then
    LISTED=$(grep -c . "$NAMES" || true)
  fi
  for N in $RTS_LIST; do
    PLANNED=$((PLANNED + 1))
    R="$OUT/$CASE.N$N"
    RC=0
    PASSED=0
    USING=0
    WHY=""
    COUNTERS=""
    START=$(date +%s)
    if [ "$LIST_RC" -ne 0 ]; then
      WHY="--list-tests exited $LIST_RC"
      RC=$LIST_RC
    elif [ "$LISTED" -eq 0 ]; then
      WHY="pattern matched 0 tests"
    elif [ "$LISTED" -lt "$MIN" ]; then
      WHY="pattern matched $LISTED tests, minimum $MIN"
    else
      timeout -s KILL "$TMO" "$BIN" -p "$PAT" -j "$N" +RTS -N"$N" -s -RTS > "$R.out" 2> "$R.err" || RC=$?
      PASSED=$(sed -n 's/^All \([0-9][0-9]*\) tests* passed.*/\1/p' "$R.out" | tail -n 1)
      PASSED=${PASSED:-0}
      if grep -Eq "using -N$N([^0-9]|\$)" "$R.err"; then
        USING=$N
      fi
      COUNTERS=$(grep '^OWNERSHIP-COUNTERS ' "$R.out" || true)
      if [ "$RC" -ne 0 ]; then
        WHY="run exited $RC"
      elif [ "$USING" -ne "$N" ]; then
        WHY="RTS evidence missing: no 'using -N$N' in the -s output"
      elif [ "$PASSED" -ne "$LISTED" ]; then
        WHY="passed $PASSED of $LISTED listed tests"
      fi
    fi
    DUR=$(( $(date +%s) - START ))
    if [ -z "$WHY" ]; then ST=pass; else ST=fail; fi
    {
      printf '{\n'
      printf '  "case": "%s",\n' "$CASE"
      printf '  "suite": "%s",\n' "$SUITE"
      printf '  "pattern": "%s",\n' "$(json_str "$PAT")"
      printf '  "min_count": %s,\n' "$MIN"
      printf '  "rts_n": %s,\n' "$N"
      printf '  "using_n": %s,\n' "$USING"
      printf '  "sha": "%s",\n' "$SHA"
      printf '  "binary": "%s",\n' "$(json_str "$BIN")"
      printf '  "binary_sha256": "%s",\n' "$BSHA"
      printf '  "nproc": %s,\n' "$NPROC"
      printf '  "rc": %s,\n' "$RC"
      printf '  "listed": %s,\n' "$LISTED"
      printf '  "passed": %s,\n' "$PASSED"
      printf '  "duration_s": %s,\n' "$DUR"
      printf '  "status": "%s",\n' "$ST"
      printf '  "reason": "%s",\n' "$(json_str "$WHY")"
      printf '  "counters": ['
      FIRST=1
      if [ -n "$COUNTERS" ]; then
        while IFS= read -r line; do
          [ "$FIRST" -eq 1 ] || printf ', '
          printf '"%s"' "$(json_str "$line")"
          FIRST=0
        done <<CEOF
$COUNTERS
CEOF
      fi
      printf ']\n}\n'
    } > "$R.json"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$CASE" "$N" "$LISTED" "$PASSED" "$RC" "$ST" "$DUR" >> "$OUT/index.tsv"
    if [ "$ST" = pass ]; then
      TOTAL_OK=$((TOTAL_OK + 1))
      echo "ok   $CASE -N$N: $PASSED/$LISTED passed (${DUR}s)"
    else
      BAD=$((BAD + 1))
      echo "FAIL $CASE -N$N: $WHY (listed $LISTED, rc $RC)"
    fi
  done
done <<TABLE_EOF
$CASE_TABLE
TABLE_EOF

# Receipt accounting: one passing receipt per planned (case, RTS).
HAVE=$(find "$OUT" -maxdepth 1 -name '*.N[0-9].json' | wc -l)
[ "$PLANNED" -gt 0 ] || fail "no cells planned"
[ "$HAVE" -eq "$PLANNED" ] || fail "receipt count $HAVE != planned $PLANNED"
echo "ownership matrix: $TOTAL_OK/$PLANNED cells passed, receipts in $OUT"
[ "$BAD" -eq 0 ] || fail "$BAD ownership cell(s) failed"
exit 0
