#!/bin/sh
# scripts/release-evidence.sh -- release-evidence manifest.
#
# ONE entry point for the C consumer/parity/release story: runs every
# driver plus the release build + clean-container install, and records
# per-driver logs plus a MANIFEST.txt. Passing here (invoked as the
# final step of scripts/run-gates.sh) means a passing release story.
#
# Layout (13 container drivers + release build + host install):
#   * each test-*.sh except test-release-install.sh runs INSIDE the
#     pinned toolchain container (per its header recipe), with the
#     standing hard rules (timeout -s KILL + --network host);
#     test-proxy-parity.sh additionally bind-mounts $HASKOKI_PROXY_DIR
#     at /opt/pkcs11-proxy-ng:ro (its default; see its header);
#   * scripts/make-release.sh rebuilds the artifact in-container;
#   * scripts/test-release-install.sh runs ON THE HOST (it drives
#     docker itself against a bare image).
#
# The driver list is explicit AND drift-checked against
# scripts/test-*.sh: a new driver script fails this manifest until it
# is classified here. Env:
#   HASKOKI_EVIDENCE_DIR  evidence root (default ./dist-release-evidence/<utc-stamp>)
#   HASKOKI_PROXY_DIR     host dir holding the canonical proxy pair (for proxy-parity)
#   HASKOKI_IMAGE         toolchain image (default haskoki-dev:ghc-9.10.3)
#
# Exit status: 0 iff every driver + the install test passes.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

IMAGE="${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVIDENCE_DIR="${HASKOKI_EVIDENCE_DIR:-$PWD/dist-release-evidence/$STAMP}"
DRIVER_TIMEOUT=1800

# The 13 container drivers, in dependency-light order (loader first:
# it is the cheapest failure signal; proxy-parity last: it needs the
# daemon + shim mount).
CONTAINER_DRIVERS="test-loader.sh test-c-abi.sh test-c-output.sh test-c-mutexes.sh test-consumers.sh test-crypto-routed.sh test-sim-threaded.sh test-finalize-race.sh test-async-attached.sh test-async-detached.sh test-control-events.sh test-lifecycle.sh test-proxy-parity.sh"

fail() {
  echo "FAIL: $1"
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker required (host invocation)"
command -v timeout >/dev/null 2>&1 || fail "timeout required (host invocation)"
mkdir -p "$EVIDENCE_DIR" || fail "cannot create $EVIDENCE_DIR"

# Drift check: the explicit list plus the host-driven install test
# must cover every test-*.sh exactly.
ON_DISK=$(cd scripts && ls test-*.sh | sort | tr '\n' ' ')
LISTED=$(echo "$CONTAINER_DRIVERS test-release-install.sh" | tr ' ' '\n' | sort | tr '\n' ' ')
[ "$ON_DISK" = "$LISTED" ] || fail "driver drift: on-disk=[$ON_DISK] listed=[$LISTED]"

echo "evidence dir: $EVIDENCE_DIR"
PASS=0
MISS=0
RESULTS=""

record() {
  # $1 = name, $2 = rc, $3 = log path
  SUM=$(sha256sum "$3" 2>/dev/null | awk '{print $1}')
  if [ "$2" -eq 0 ]; then
    echo "PASS: $1 (log: $3)"
    PASS=$((PASS + 1))
    RESULTS="$RESULTS$1 PASS $SUM
"
  else
    echo "MISS: $1 rc=$2 (log: $3)"
    MISS=$((MISS + 1))
    RESULTS="$RESULTS$1 MISS(rc=$2) $SUM
"
  fi
}

for d in $CONTAINER_DRIVERS; do
  LOG="$EVIDENCE_DIR/$d.log"
  echo "--- driver: $d"
  if [ "$d" = "test-proxy-parity.sh" ] && [ -n "${HASKOKI_PROXY_DIR:-}" ]; then
    [ -f "$HASKOKI_PROXY_DIR/pkcs11-proxy-ng" ] || fail "proxy dir lacks daemon: $HASKOKI_PROXY_DIR"
    timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
      -v "$PWD:/work" -w /work \
      -v "$HASKOKI_PROXY_DIR:/opt/pkcs11-proxy-ng:ro" \
      "$IMAGE" "scripts/$d" >"$LOG" 2>&1
    RC=$?
  else
    timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
      -v "$PWD:/work" -w /work \
      "$IMAGE" "scripts/$d" >"$LOG" 2>&1
    RC=$?
  fi
  record "$d" "$RC" "$LOG"
done

echo "--- release build: make-release.sh"
timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
  -v "$PWD:/work" -w /work \
  "$IMAGE" scripts/make-release.sh >"$EVIDENCE_DIR/make-release.sh.log" 2>&1
record "make-release.sh" "$?" "$EVIDENCE_DIR/make-release.sh.log"

echo "--- host install test: test-release-install.sh"
timeout -s KILL 900 bash scripts/test-release-install.sh \
  >"$EVIDENCE_DIR/test-release-install.sh.log" 2>&1
record "test-release-install.sh" "$?" "$EVIDENCE_DIR/test-release-install.sh.log"

{
  echo "release evidence manifest"
  echo "stamp: $STAMP (utc)"
  echo "rev: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "image: $IMAGE"
  echo "proxy dir: ${HASKOKI_PROXY_DIR:-<unset>}"
  echo "pass: $PASS miss: $MISS"
  printf '%s' "$RESULTS"
} >"$EVIDENCE_DIR/MANIFEST.txt"
cat "$EVIDENCE_DIR/MANIFEST.txt"

if [ "$MISS" -ne 0 ]; then
  fail "$MISS of $((PASS + MISS)) evidence steps missed"
fi
echo "PASS: release-evidence.sh ($PASS/$((PASS + MISS)) steps passing)"
