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
#                         (default: pkcs11-check; CI passes
#                         "uv run --project pkcs11-check pkcs11-check")
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

P11="${PKCS11_CHECK:-pkcs11-check}"
PIN="${PKCS11_CHECK_PIN:-1234}"
SO_PIN="${PKCS11_CHECK_SO_PIN:-5678}"

echo "lane: $LANE"
echo "module: $SO"
echo "config: $CFG"

# Word-split entry point is the interface.
# shellcheck disable=SC2086
$P11 doctor --module "$SO" || fail "doctor failed (module must load + seat token)"

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
# Word-split entry point + extra args are the interface.
# shellcheck disable=SC2086
$P11 test --module "$SO" --slot 0 --isolation auto --timeout 180 \
  --marker "$MARKER" --output json --output-file "$OUT" \
  --pin "$PIN" --so-pin "$SO_PIN" ${PKCS11_CHECK_EXTRA_ARGS:-} || RC=$?
echo "pkcs11-check exit code: $RC"
# 0 = all pass; 1 = provider findings (expected, captured in $OUT).
# >= 2 = setup/usage error: the run never happened, fail loudly.
[ "$RC" -ge 2 ] && fail "pkcs11-check setup error (rc=$RC)"
[ -f "$OUT" ] || fail "missing results file: $OUT"
python3 - "$OUT" <<'PY' || fail "cannot parse results file"
import json, sys
s = json.load(open(sys.argv[1])).get("summary", {})
g = s.get
print("lane summary: %d tests - %d passed, %d failed, %d crashed, "
      "%d timeout, %d xfailed, %d skipped" % (
          g("total", 0), g("passed", 0), g("failed", 0), g("crashed", 0),
          g("timeout", 0), g("xfailed", 0), g("skipped", 0)))
PY
echo "PASS: ci-pkcs11-lane.sh ($LANE; findings in $OUT)"
