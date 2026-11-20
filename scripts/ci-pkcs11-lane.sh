#!/bin/sh
# scripts/ci-pkcs11-lane.sh -- pkcs11-check conformance lane (fast or kat).
#
# Runs the external pkcs11-check consumer against a release artifact:
# `doctor` first (hard gate: the module must load, seat one token,
# and advertise the mechanism catalog), then `test` with the lane
# markers. Test findings (exit 1) are REPORTED, not gating: this
# module is a demonstrator whose honest refusals the oracle records
# as findings. Exit >= 2 (setup/usage error) fails the lane.
#
# Lanes:
#   fast  offline markers, no vector data:
#         'not (wycheproof or acvp or cctv or stress or fuzz or slow)'
#   kat   full markers over fetched vector data: 'not (stress or fuzz)'
#         (requires PKCS11_CHECK_DATA_DIR with wycheproof/acvp/cctv/
#         x509-limbo content; see `pkcs11-check fetch-data all`)
#
# Usage:
#   scripts/ci-pkcs11-lane.sh fast <artifact-dir> [results.json]
#   scripts/ci-pkcs11-lane.sh kat <artifact-dir> [results.json]
#
# Env:
#   PKCS11_CHECK          pkcs11-check entry point, words allowed
#                         (default: pkcs11-check). Ignored for launching
#                         when PKCS11_CHECK_DIR is set (noted on stdout).
#   PKCS11_CHECK_DIR      checker checkout dir for gated runs: the lane
#                         launches "uv run --project DIR pkcs11-check" and
#                         records DIR's HEAD (must be clean) at
#                         provenance.framework.commit in the results.
#                         Unset (ad-hoc runs): no envelope is written and
#                         the baseline gate will refuse the results.
#   HASKOKI_CONFIG        backend config (default: scripts/ci-backend.toml)
#   PKCS11_CHECK_DATA_DIR vector data root (kat lane requires content)
#   PKCS11_CHECK_PIN      user PIN (default 1234, the demo token PIN)
#   PKCS11_CHECK_SO_PIN   SO PIN (default 5678, the demo token PIN)
#   PKCS11_CHECK_EXTRA_ARGS extra `test` args (word-split)
#
# Exit status: 0 on doctor-pass + test exit 0/1; 1 otherwise.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

[ $# -ge 2 ] || fail "usage: ci-pkcs11-lane.sh fast|kat <artifact-dir> [results.json]"
LANE="$1"
ART="$2"
OUT="${3:-pkcs11-$LANE-results.json}"

[ "$LANE" = "fast" ] || [ "$LANE" = "kat" ] || fail "lane must be fast or kat"
SO="$ART/lib/libhaskoki.so"
[ -f "$SO" ] || fail "artifact module missing: $SO (run: scripts/make-release.sh)"
CFG="${HASKOKI_CONFIG:-scripts/ci-backend.toml}"
[ -f "$CFG" ] || fail "backend config missing: $CFG"
export HASKOKI_CONFIG="$CFG"

# No LD_LIBRARY_PATH needed: the artifact module resolves its bundled
# closure from its own directory ($ORIGIN RUNPATH). Deliberately left
# unset here so the lane proves the bundle is self-resolving.

CHECKER_DIR="${PKCS11_CHECK_DIR:-}"
CHECKER_SHA=""
if [ -n "$CHECKER_DIR" ]; then
  [ -d "$CHECKER_DIR" ] || fail "PKCS11_CHECK_DIR is not a directory: $CHECKER_DIR"
  CHECKER_DIR=$(cd "$CHECKER_DIR" && pwd) || fail "cannot resolve $CHECKER_DIR"
  # A single directory binds the recorded SHA to the launched checker:
  # it must be the checker project root and git-clean, so the SHA
  # identifies repeatable content. Container-proof git invocation
  # (check-findings-ledger.py precedent: safe.directory).
  [ -e "$CHECKER_DIR/.git" ] || fail "$CHECKER_DIR is not a git checkout"
  [ -f "$CHECKER_DIR/pyproject.toml" ] || fail "$CHECKER_DIR has no pyproject.toml (not the checker root?)"
  [ -d "$CHECKER_DIR/src/pkcs11_check" ] || fail "$CHECKER_DIR has no src/pkcs11_check (not the checker root?)"
  GIT_STATUS_OUT=$(git -c safe.directory="$CHECKER_DIR" -C "$CHECKER_DIR" status --porcelain) \
    || fail "cannot inspect cleanliness of $CHECKER_DIR"
  [ -z "$GIT_STATUS_OUT" ] \
    || fail "checker checkout $CHECKER_DIR is dirty (gated runs need a clean tree)"
  CHECKER_SHA=$(git -c safe.directory="$CHECKER_DIR" -C "$CHECKER_DIR" rev-parse HEAD) \
    || fail "cannot resolve checker HEAD in $CHECKER_DIR"
  echo "checker: $CHECKER_DIR @ $CHECKER_SHA"
fi

P11="${PKCS11_CHECK:-pkcs11-check}"
if [ -n "$CHECKER_DIR" ]; then
  [ -z "${PKCS11_CHECK:-}" ] || echo "note: PKCS11_CHECK_DIR takes precedence over PKCS11_CHECK for gated runs"
fi

run_p11() {
  if [ -n "$CHECKER_DIR" ]; then
    uv run --project "$CHECKER_DIR" pkcs11-check "$@"
  else
    # Word-split entry point is the ad-hoc interface.
    # shellcheck disable=SC2086
    $P11 "$@"
  fi
}
PIN="${PKCS11_CHECK_PIN:-1234}"
SO_PIN="${PKCS11_CHECK_SO_PIN:-5678}"

echo "lane: $LANE"
echo "module: $SO"
echo "config: $CFG"

run_p11 doctor --module "$SO" || fail "doctor failed (module must load + seat token)"

if [ "$LANE" = "kat" ]; then
  DATA="${PKCS11_CHECK_DATA_DIR:-}"
  [ -n "$DATA" ] || fail "kat lane needs PKCS11_CHECK_DATA_DIR"
  [ -d "$DATA/wycheproof" ] || [ -d "$DATA/acvp" ] || [ -d "$DATA/cctv" ] || [ -d "$DATA/x509-limbo" ] \
    || fail "kat lane needs fetched vectors under $DATA (run: pkcs11-check fetch-data all)"
  MARKER='not (stress or fuzz)'
  export PKCS11_CHECK_DATA_DIR="$DATA"
else
  MARKER='not (wycheproof or acvp or cctv or stress or fuzz or slow)'
fi
echo "marker: $MARKER"

RC=0
# Fresh output only: the checker writes a unique staging file, never $OUT
# directly, so a failed run cannot stamp or re-read a stale report.
STAGE="$OUT.stage.$$"
rm -f "$STAGE"
trap 'rm -f "$STAGE"' EXIT
# Word-split extra args are the interface.
# shellcheck disable=SC2086
run_p11 test --module "$SO" --slot 0 --isolation auto --timeout 180 \
  --marker "$MARKER" --output json --output-file "$STAGE" \
  --pin "$PIN" --so-pin "$SO_PIN" ${PKCS11_CHECK_EXTRA_ARGS:-} || RC=$?
echo "pkcs11-check exit code: $RC"
# 0 = all pass; 1 = provider findings (expected, captured fresh).
# >= 2 = setup/usage error: the run never happened, fail loudly.
if [ "$RC" -ge 2 ]; then
  rm -f "$STAGE" "$OUT"
  fail "pkcs11-check setup error (rc=$RC)"
fi
if [ ! -f "$STAGE" ]; then
  rm -f "$STAGE" "$OUT"
  fail "checker produced no fresh results (stale output removed)"
fi
CHECKER_SHA="$CHECKER_SHA" STAGE="$STAGE" OUT="$OUT" python3 - <<'PY' || { rm -f "$STAGE" "$OUT"; fail "cannot publish results to $OUT"; }
import json, os, sys
stage, out, sha = (os.environ["STAGE"], os.environ["OUT"],
                   os.environ["CHECKER_SHA"])
try:
    with open(stage, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("tool") != "pkcs11-check" or data.get("kind") != "test-run":
        print("staging is not a pkcs11-check test-run report",
              file=sys.stderr)
        sys.exit(1)
    s = data.get("summary", {})
    g = s.get
    print("lane summary: %d tests - %d passed, %d failed, %d crashed, "
          "%d timeout, %d xfailed, %d skipped" % (
              g("total", 0), g("passed", 0), g("failed", 0), g("crashed", 0),
              g("timeout", 0), g("xfailed", 0), g("skipped", 0)))
    if sha:
        fw = data["provenance"]["framework"]
        if not isinstance(fw, dict):
            print("staging provenance.framework is not an object",
                  file=sys.stderr)
            sys.exit(1)
        stamped = fw.get("commit")
        if stamped and stamped != sha:
            print("staging carries foreign checker commit %s "
                  "(launched %s)" % (stamped, sha), file=sys.stderr)
            sys.exit(1)
        fw["commit"] = sha
        fw["commit_source"] = "ci-pkcs11-lane.sh PKCS11_CHECK_DIR rev-parse"
    with open(stage, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
    os.replace(stage, out)
except (OSError, ValueError, KeyError, TypeError) as e:
    print("cannot publish results: %s" % e, file=sys.stderr)
    sys.exit(1)
PY
if [ -n "$CHECKER_DIR" ]; then
  echo "envelope: checker $CHECKER_SHA recorded in $OUT"
else
  echo "note: no PKCS11_CHECK_DIR: results carry no checker SHA (the baseline gate will refuse them)"
fi
echo "PASS: ci-pkcs11-lane.sh ($LANE; findings in $OUT)"
