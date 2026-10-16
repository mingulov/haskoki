#!/bin/sh
# scripts/test-ownership-matrix.sh -- private-RTS ownership fixture matrix.
#
# Runs the named ownership fixtures (the ownership matrix cases of the concurrency plan)
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

# case|suite|tasty-pattern|min-count|status|counters
# min-count is the floor observed in the real run (a shrinking suite
# fails). counters=yes: the case must print OWNERSHIP-COUNTERS lines
# (HASKOKI_OWNERSHIP_COUNTERS=1), every value 0.
# The counters column is `no`, or the exact comma-separated set of test=
# labels the case must print (one per gated test): a test that stops
# emitting, or a stray label, fails the cell.
# m2-lifetime-gate: gate-race-oneshot, gate-race-init, gate-race-import and
# gate-race-export never emit (no native outstanding counter) and are
# excluded from its label set on purpose.
# m3-standalone-ownership: block-wait-rejects-other-block-reasons never
# emits (a helper negative-control with no resource to count) and is
# excluded from its label set on purpose.
# Patterns are tasty 1.5 awk expressions over the test path
# ($1 = suite root, $2 = top group, $3 = subgroup). They must not
# contain `|`. Rows for later fixtures are appended as `pending`
# until those fixtures exist.
CASE_TABLE=$(cat <<'TABLE'
m1-native-transfers|model|$2 == "Ownership" && $3 == "native ownership transfers"|12|active|gated-adoption-alloc,gated-adoption-load,gated-adoption-park,gated-copy-fault,gated-copy-park,gated-digest-alloc,gated-final-fault,gated-final-park,gated-init-alloc,gated-live-300,gated-normal-zero,gated-pair-between
m1-openssl4-engine|engine|$2 == "openssl4 engine"|70|active|no
m1-acquisition-hooks|engine|$2 == "Acquisition hooks"|32|active|no
m2-lease-protocol|model|$2 == "Ownership" && $3 == "lease protocol"|6|active|no
m2-lifetime-gate|model|$2 == "Ownership" && $3 == "lifetime gate"|12|active|gate-cancel-closing,gate-close-after-interrupt,gate-close-waits-borrow,gate-close-waits-final,gate-race-final,gate-race-release,gate-race-update,gate-simultaneous-close
m3-handle-registry|model|$2 == "Ownership" && $3 == "handle registry"|11|active|handle-admission-storm,handle-close-race,handle-kill-storm,handle-resolve-retire,handle-resolve-then-close,handle-retire-then-use
m3-ffi-acquisition|model|$2 == "FFI acquisition" && $3 != "standalone ownership"|23|active|admitted-calls-run-close-retires-the-gate,borrowed-start-works,close-one-keeps-the-other-context-live,close-waits-for-an-entered-caller,concurrent-entry-races-close-cleanly,join-acquire-publishes-a-live-handle,join-handoff-publishes-a-live-handle,kill-after-join-commit-cancels-before-publish,kill-during-acquire-rolls-back-and-nulls,kill-in-the-join-handoff-cancels-the-fresh-join,kill-in-the-submit-transfer-cancels-the-fresh-job,killed-close-releases-retry-completes-teardown
m3-async-engine|engine|$2 == "Async engine"|25|active|caseasyncadmissionwidths,caseasyncborrowedownership,caseasynccleanupsurface,caseasyncpubliccompletion,ffi-bogus-handle-refused-nothing-touched,ffi-cancel-frees-late-use-is-stale,ffi-close-drains-pending-jobs-exactly-once,ffi-close-one-keeps-other-context-live,ffi-concurrent-cancel-exactly-one-wins,ffi-concurrent-complete-single-delivery,ffi-cross-context-handle-use-is-stale,ffi-digest-pending-canaries-exact-delivery,ffi-drive-error-frees-the-handle-exactly-once
m4-store-contract|storage|$2 == "store contract"|123|active|no
m4-multi-session|storage|$2 == "Multi-session store"|34|active|no
m5-attachment-claims|model|$2 == "Ownership" && $3 == "attachment claims"|5|active|claim-rival-refusal
m5-detached-jobs|model|$2 == "Detached jobs"|55|active|a-cancelled-parked-claim-frees-the-id-for-the-other-context,interruption-after-start-retires-the-fresh-job,retire-rolls-a-racing-claim-back-the-join-cannot-commit
m5-scoped-detach-leases|model|$2 == "Scoped detach leases"|9|active|no
m6-two-contexts-distinct-ids|model|$2 == "Detached jobs" && /two contexts on one store/|1|active|no
m6-store-wide-counter|model|$2 == "Detached jobs" && /two tokens share the store-wide counter/|1|active|no
m7-attached-async|model|$2 == "Attached async"|37|active|byte-budget-clears-suite-shaped-fills-with-headroom,byte-evicted-store-delivery-retry-cancel-semantics-unchanged,byte-retention-bound-n-max-size-digests-keep-bytes-within-budget,capped-store-delivery-retry-cancel-semantics-unchanged,reap-drops-tombstones-live-jobs-survive,retention-bound-n-delivered-digests-keep-at-most-cap-tombstones,sync-sessions-stay-synchronous-under-async-storm
m7-retirement|model|$2 == "Ownership" && /retire/|5|active|no
m3-standalone-ownership|model|$2 == "FFI acquisition" && $3 == "standalone ownership"|29|active|store-box-killed-after-store-open-closes-the-store,store-box-killed-after-token-setup-closes-the-store,store-box-killed-during-token-load-closes-the-store,sqlite-store-box-killed-after-token-setup-releases-its-lock,context-killed-after-backend-open-closes-the-backend,context-killed-after-session-open-closes-the-backend,context-killed-after-pointer-allocation-frees-it-unregistered,store-bound-context-killed-after-reload-leaves-the-box-usable,export-store-open-residue-is-recovered-by-the-next-open,closer-killed-in-the-store-wait-stays-closing-and-retries,closer-killed-in-a-job-lease-wait-cancels-once-on-retry,closer-killed-in-the-backend-gate-wait-frees-the-env-once-on-retry,store-failure-in-retirement-still-closes-and-keeps-the-record-joinable,table-close-phases-move-only-forward-after-teardown-starts,unknown-registry-key-refuses-before-dereference,hook-only-registry-key-refuses-after-its-hook,close-of-an-unknown-key-nulls-the-slot-only,close-with-a-throwing-retire-resumes-on-retry,close-with-a-throwing-free-resumes-on-retry,store-throw-in-retirement-still-closes-and-keeps-the-record-joinable,value-level-close-killed-in-a-lease-wait-resumes,null-slot-and-null-pointer-closes-are-silent,repeated-context-close-frees-and-retires-once,failed-store-close-keeps-the-box-slot-until-a-retry-succeeds,store-box-close-killed-in-the-lock-wait-keeps-the-box,standalone-churn-leaves-no-orphan-roots-or-native-envs,joined-cleanup-lets-the-same-store-reopen,joined-cleanup-lets-the-same-sqlite-store-reopen
wp09-pending|model|-|0|pending|no
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

# tree_clean: git status --porcelain empty (a receipt from a dirty tree
# is identifiable). Unknown (no git) counts as not clean.
if [ -n "$(git status --porcelain 2>/dev/null || echo unknown)" ]; then
  TREE_CLEAN=false
else
  TREE_CLEAN=true
fi

NPROC=$(nproc 2>/dev/null || echo 0)
BAD=0
PLANNED=0
TOTAL_OK=0
printf 'case\trts\tlisted\tpassed\trc\tstatus\tduration_s\n' > "$OUT/index.tsv"

while IFS='|' read -r CASE SUITE PAT MIN STATUS CTR; do
  [ -n "$CASE" ] || continue
  case "$CASE" in \#*) continue ;; esac
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
  timeout -s KILL "$TMO" "$BIN" -p "$PAT" --list-tests < /dev/null > "$NAMES" 2> "$OUT/$CASE.list.err" || LIST_RC=$?
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
      HASKOKI_OWNERSHIP_COUNTERS=1 timeout -s KILL "$TMO" "$BIN" -p "$PAT" -j "$N" +RTS -N"$N" -s -RTS < /dev/null > "$R.out" 2> "$R.err" || RC=$?
      PASSED=$(sed -n 's/^All \([0-9][0-9]*\) tests* passed.*/\1/p' "$R.out" | tail -n 1)
      PASSED=${PASSED:-0}
      if grep -Eq "using -N$N([^0-9]|\$)" "$R.err"; then
        USING=$N
      fi
      # Unanchored: tasty may have printed the test name on the same line.
      COUNTERS=$(grep -o 'OWNERSHIP-COUNTERS case=.*' "$R.out" || true)
      if [ "$RC" -ne 0 ]; then
        WHY="run exited $RC"
      elif [ "$USING" -ne "$N" ]; then
        WHY="RTS evidence missing: no 'using -N$N' in the -s output"
      elif [ "$PASSED" -ne "$LISTED" ]; then
        WHY="passed $PASSED of $LISTED listed tests"
      elif [ "$CTR" != no ]; then
        if [ -z "$COUNTERS" ]; then
          WHY="counter line missing: no OWNERSHIP-COUNTERS line for $CASE"
        else
          # Every line belongs to this case; every k=v after case/test
          # is 0; the set of test= labels equals the case's required
          # set (a gated test that stops emitting fails).
          WHY=$(printf '%s\n' "$COUNTERS" | awk -v c="$CASE" -v req="$CTR" '
            BEGIN { n = split(req, r, ","); for (i = 1; i <= n; i++) want[r[i]] = 1 }
            { if ($2 != "case=" c) { bad = 1; print "counter line for another case: " $2; exit }
              if ($3 !~ /^test=./) { bad = 1; print "counter line has no test= label"; exit }
              lbl = substr($3, 6); seen[lbl] = 1
              if (!(lbl in want)) { bad = 1; print "unexpected counter label: " lbl; exit }
              for (i = 4; i <= NF; i++) {
                split($i, kv, "=")
                if (kv[2] !~ /^[0-9]+$/ || kv[2] != 0) { bad = 1; print "counter nonzero: " $i " (" lbl ")"; exit }
              } }
            END { if (!bad) for (i = 1; i <= n; i++) if (!(r[i] in seen)) { print "counter label missing: " r[i]; exit } }')
        fi
      fi
    fi
    DUR=$(( $(date +%s) - START ))
    CTR_REQ=true
    [ "$CTR" != no ] || CTR_REQ=false
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
      printf '  "tree_clean": %s,\n' "$TREE_CLEAN"
      printf '  "counters_required": %s,\n' "$CTR_REQ"
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
