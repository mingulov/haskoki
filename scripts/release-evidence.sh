#!/bin/sh
# scripts/release-evidence.sh -- release-evidence manifest.
#
# ONE entry point for the C consumer/parity/release story: runs every
# driver plus the ABI sensitivity leg (`test-c-abi.sh --negative`,
# T-1) plus the release build + clean-container install, and records
# per-driver logs plus a MANIFEST.txt. Passing here (invoked as the
# final step of scripts/run-gates.sh) means a passing release story.
#
# Layout (15 container drivers + release build + 2 host drivers +
# 1 nested child), from scripts/driver-inventory.json:
#   * each role=container driver runs INSIDE the pinned toolchain
#     container (per its header recipe), with the standing hard rules
#     (timeout -s KILL + --network host); test-proxy-parity.sh
#     additionally bind-mounts $HASKOKI_PROXY_DIR at
#     /opt/pkcs11-proxy-ng:ro (its default; see its header);
#   * the ABI sensitivity leg (`test-c-abi.sh --negative`) runs
#     INSIDE the container right after the driver loop and is
#     recorded as its own manifest line (a leg, not a 16th driver);
#   * scripts/make-release.sh rebuilds the artifact in-container;
#   * the runner then stages ONE fresh tarball from that just-built
#     bundle tree into the evidence dir and passes its exact path
#     (plus the exact tree path) to scripts/test-release-install.sh,
#     which runs ON THE HOST (it drives docker itself against a bare
#     image). No default pathname, older archive or failed-build
#     output can satisfy this prerequisite: the install leg never
#     falls back to dist-release/*.tar.gz on its own;
#   * scripts/test-demo-image.sh runs ON THE HOST in four phases
#     (build once, then contracts/full/compare against the frozen
#     image id — the CI sharding, serialized): it rebuilds the demo
#     image and drives the entrypoint lanes itself (measured serial
#     wall 84-113 min on v0.5.0.0, so one shared 90 min guard fired
#     after every leg passed). Each phase runs under its own
#     `timeout -s KILL 5400` with its own out dir and log under
#     $EVIDENCE_DIR/demo-image/<phase>, recorded as ONE manifest
#     step whose log names every phase, exit, duration and log;
#   * role=nested drivers (test-demo-onboarding.sh, under
#     test-demo-image.sh) run ONLY inside their parent and are never
#     executed standalone here, so the parent pipeline runs once.
#
#   * role=qualification drivers (test-ownership-matrix.sh) are owned
#     by the inventory but SKIPPED here: they belong to the
#     qualification workflow and stay outside the 19-step manifest;
# The driver inventory is the single source of truth AND is
# drift-checked against scripts/test-*.sh: a new driver script fails
# this manifest until it is classified there, and an inventory entry
# without its file (or with a bad role/parent/cycle) fails too. Env:
#   HASKOKI_EVIDENCE_DIR  evidence root (default ./dist-release-evidence/<utc-stamp>)
#   HASKOKI_PROXY_DIR     host dir holding the canonical proxy pair (for proxy-parity)
#   HASKOKI_PROXY_PORT    loopback listener port for the parity leg (default 17512)
#   HASKOKI_IMAGE         toolchain image (default haskoki-dev:ghc-9.10.3)
#   HASKOKI_INSTALL_IMAGE bare install image (default ubuntu:26.04)
#
# Exit status: 0 iff every driver + build + both host tests pass. A
# failed bundle build marks the dependent install BLOCKED (still a
# miss overall) while independent drivers keep their own evidence.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

IMAGE="${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
INSTALL_IMAGE="${HASKOKI_INSTALL_IMAGE:-ubuntu:26.04}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVIDENCE_DIR="${HASKOKI_EVIDENCE_DIR:-$PWD/dist-release-evidence/$STAMP}"
DRIVER_TIMEOUT=1800
INVENTORY="scripts/driver-inventory.json"

fail() {
  echo "FAIL: $1"
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker required (host invocation)"
command -v timeout >/dev/null 2>&1 || fail "timeout required (host invocation)"
command -v python3 >/dev/null 2>&1 || fail "python3 required (inventory validation)"
[ -f "$INVENTORY" ] || fail "driver inventory missing: $INVENTORY"

# Validate the inventory and cover every test-*.sh exactly once. Prints
# shell assignments (names are charset-restricted, so eval is safe);
# any drift/invalid entry fails the manifest before anything runs.
INV_OUT=$(python3 - "$INVENTORY" "scripts" <<'PYEOF'
import json, os, re, sys
inv_path, scripts_dir = sys.argv[1], sys.argv[2]
def die(msg):
    print(f"FAIL: driver inventory: {msg}", file=sys.stderr)
    sys.exit(1)
try:
    inv = json.load(open(inv_path))
except Exception as e:
    die(f"unparseable JSON: {e}")
drivers = inv.get("drivers") if isinstance(inv, dict) else None
if not isinstance(drivers, list) or not drivers:
    die("missing non-empty 'drivers' array")
seen = {}
order = []
for i, d in enumerate(drivers):
    if not isinstance(d, dict):
        die(f"entry {i} is not an object")
    name, role, parent = d.get("name"), d.get("role"), d.get("parent")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.sh", name):
        die(f"entry {i} has bad name: {name!r}")
    if name in seen:
        die(f"duplicate driver: {name}")
    if role not in ("container", "host", "nested", "qualification"):
        die(f"{name}: bad role: {role!r}")
    if role in ("container", "host", "qualification"):
        if parent is not None:
            die(f"{name}: top-level {role} driver must have null parent")
    elif not isinstance(parent, str) or parent == name:
        die(f"{name}: bad nested parent: {parent!r}")
    seen[name] = (role, parent)
    order.append(name)
on_disk = sorted(f for f in os.listdir(scripts_dir)
                 if f.startswith("test-") and f.endswith(".sh"))
for f in on_disk:
    if f not in seen:
        die(f"unowned driver on disk (classify in inventory): {f}")
for name in order:
    if not os.path.isfile(os.path.join(scripts_dir, name)):
        die(f"missing driver file: {name}")
def resolve(n, chain):
    _role, parent = seen[n]
    if parent is None:
        return
    if parent not in seen:
        die(f"{n}: unknown nested parent: {parent}")
    if parent in chain:
        die(f"nested cycle: {' -> '.join([*chain, parent])}")
    resolve(parent, [*chain, parent])
for n in order:
    if seen[n][0] == "nested":
        resolve(n, [n])
container = [n for n in order if seen[n][0] == "container"]
host = [n for n in order if seen[n][0] == "host"]
nested = [f"{n}:{seen[n][1]}" for n in order if seen[n][0] == "nested"]
print(f"CONTAINER_DRIVERS='{' '.join(container)}'")
print(f"HOST_DRIVERS='{' '.join(host)}'")
print(f"NESTED_DRIVERS='{' '.join(nested)}'")
PYEOF
) || fail "driver inventory invalid (see above)"
eval "$INV_OUT"

mkdir -p "$EVIDENCE_DIR" || fail "cannot create $EVIDENCE_DIR"

# Image identity for the manifest. Fail closed when the daemon cannot
# answer: unidentified images must not produce a passing manifest.
IMAGE_ID=$(timeout -s KILL 60 docker inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null) \
  || fail "cannot verify toolchain image identity: $IMAGE"
[ -n "$IMAGE_ID" ] || fail "cannot verify toolchain image identity: $IMAGE"

echo "evidence dir: $EVIDENCE_DIR"
echo "image: $IMAGE ($IMAGE_ID)"
PASS=0
MISS=0
BLOCKED=0
RESULTS=""

# sq <text>: single-quote-escape for the cmd=/reason= manifest fields.
sq() {
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
}

record() {
  # $1 = name, $2 = rc, $3 = log path, $4 = command
  SUM=$(sha256sum "$3" 2>/dev/null | awk '{print $1}')
  CMD_ESC=$(sq "$4")
  if [ "$2" -eq 0 ]; then
    echo "PASS: $1 (log: $3)"
    PASS=$((PASS + 1))
    RESULTS="$RESULTS$1 PASS rc=$2 cmd='$CMD_ESC' log=$SUM
"
  else
    echo "MISS: $1 rc=$2 (log: $3)"
    MISS=$((MISS + 1))
    RESULTS="$RESULTS$1 MISS rc=$2 cmd='$CMD_ESC' log=$SUM
"
  fi
}

record_blocked() {
  # $1 = name, $2 = log path, $3 = command, $4 = reason
  SUM=$(sha256sum "$2" 2>/dev/null | awk '{print $1}')
  CMD_ESC=$(sq "$3")
  WHY_ESC=$(sq "$4")
  echo "BLOCKED: $1 ($4; log: $2)"
  MISS=$((MISS + 1))
  BLOCKED=$((BLOCKED + 1))
  RESULTS="$RESULTS$1 BLOCKED rc=- cmd='$CMD_ESC' log=$SUM reason='$WHY_ESC'
"
}

# DEMO-PHASES-BEGIN -- extractable block: the verification runbook
# copies these two functions verbatim to run the demo-image leg
# standalone against an evidence dir. Keep them free of record/fail
# calls: results come back in DEMO_RC/DEMO_CMD/DEMO_LOG/DEMO_IMAGE_ID
# so the caller records ONE manifest step.
run_demo_phase() {
  # $1=name $2=out-dir $3=log $4=image $5=driver-phase. Runs one
  # demo-image phase under its own 5400s kill guard and appends one
  # receipt line (exit, duration, log) to the combined DEMO_LOG.
  # Sets DEMO_PHASE_RC to the phase exit status.
  _DP_NAME="$1"; _DP_OUT="$2"; _DP_LOG="$3"; _DP_IMAGE="$4"; _DP_PHASE="$5"
  if ! mkdir -p "$_DP_OUT"; then
    echo "phase $_DP_NAME: cannot create $_DP_OUT" >>"$DEMO_LOG"
    DEMO_PHASE_RC=1
    return
  fi
  _DP_START=$(date +%s)
  HASKOKI_DEMO_IMAGE="$_DP_IMAGE" HASKOKI_DEMO_TEST_OUT="$_DP_OUT" \
    timeout -s KILL 5400 bash scripts/test-demo-image.sh "$_DP_PHASE" \
    >"$_DP_LOG" 2>&1
  DEMO_PHASE_RC=$?
  _DP_DUR=$(($(date +%s) - _DP_START))
  echo "phase $_DP_NAME: rc=$DEMO_PHASE_RC duration=${_DP_DUR}s log=$_DP_LOG" >>"$DEMO_LOG"
}

run_demo_image_phases() {
  # $1=evidence dir. Build the demo image once, freeze its immutable
  # id (the same `docker inspect .Id` the driver itself freezes to),
  # then run the contracts/full/compare test phases against that id.
  # Stop-after-first-failure: a failed phase (or an unresolvable
  # image id) leaves every later phase NOT RUN and fails the step.
  # Sets DEMO_RC (0 iff build + all three phases exit 0), DEMO_CMD
  # (all four phase commands, joined as the && chain they form),
  # DEMO_LOG (combined log) and DEMO_IMAGE_ID.
  _DI_EV="$1"
  _DI_DIR="$_DI_EV/demo-image"
  DEMO_LOG="$_DI_EV/test-demo-image.sh.log"
  DEMO_RC=1
  DEMO_IMAGE_ID=""
  _DI_VER=$(grep -m1 '^version:' haskoki.cabal 2>/dev/null | awk '{print $2}')
  _DI_TAG="${HASKOKI_DEMO_IMAGE:-haskoki-demo:${_DI_VER:-unknown}}"
  DEMO_CMD="HASKOKI_DEMO_IMAGE=$_DI_TAG HASKOKI_DEMO_TEST_OUT=$_DI_DIR/build timeout -s KILL 5400 bash scripts/test-demo-image.sh build && HASKOKI_DEMO_IMAGE=<frozen-id> HASKOKI_DEMO_TEST_OUT=$_DI_DIR/contracts timeout -s KILL 5400 bash scripts/test-demo-image.sh contracts && HASKOKI_DEMO_IMAGE=<frozen-id> HASKOKI_DEMO_TEST_OUT=$_DI_DIR/full timeout -s KILL 5400 bash scripts/test-demo-image.sh full && HASKOKI_DEMO_IMAGE=<frozen-id> HASKOKI_DEMO_TEST_OUT=$_DI_DIR/compare timeout -s KILL 5400 bash scripts/test-demo-image.sh compare"
  mkdir -p "$_DI_DIR" || return 0
  : >"$DEMO_LOG" || return 0
  echo "demo-image phases: build then contracts/full/compare (each timeout -s KILL 5400)" >>"$DEMO_LOG"
  if [ -z "$_DI_VER" ]; then
    echo "image tag: cannot parse version from haskoki.cabal" >>"$DEMO_LOG"
    for _DI_P in build contracts full compare; do
      echo "phase $_DI_P: NOT RUN (no version)" >>"$DEMO_LOG"
    done
    return 0
  fi
  echo "build tag: $_DI_TAG" >>"$DEMO_LOG"
  run_demo_phase build "$_DI_DIR/build" "$_DI_DIR/build.log" "$_DI_TAG" build
  if [ "$DEMO_PHASE_RC" -ne 0 ]; then
    for _DI_P in contracts full compare; do
      echo "phase $_DI_P: NOT RUN (build rc=$DEMO_PHASE_RC)" >>"$DEMO_LOG"
    done
    DEMO_RC=$DEMO_PHASE_RC
    return 0
  fi
  DEMO_IMAGE_ID=$(timeout -s KILL 60 docker inspect --format '{{.Id}}' "$_DI_TAG" 2>/dev/null) || DEMO_IMAGE_ID=""
  if [ -z "$DEMO_IMAGE_ID" ]; then
    echo "image id: cannot resolve $_DI_TAG (fail closed)" >>"$DEMO_LOG"
    for _DI_P in contracts full compare; do
      echo "phase $_DI_P: NOT RUN (no image id)" >>"$DEMO_LOG"
    done
    DEMO_RC=1
    return 0
  fi
  echo "image id: $DEMO_IMAGE_ID ($_DI_TAG)" >>"$DEMO_LOG"
  DEMO_CMD="HASKOKI_DEMO_IMAGE=$_DI_TAG HASKOKI_DEMO_TEST_OUT=$_DI_DIR/build timeout -s KILL 5400 bash scripts/test-demo-image.sh build && HASKOKI_DEMO_IMAGE=$DEMO_IMAGE_ID HASKOKI_DEMO_TEST_OUT=$_DI_DIR/contracts timeout -s KILL 5400 bash scripts/test-demo-image.sh contracts && HASKOKI_DEMO_IMAGE=$DEMO_IMAGE_ID HASKOKI_DEMO_TEST_OUT=$_DI_DIR/full timeout -s KILL 5400 bash scripts/test-demo-image.sh full && HASKOKI_DEMO_IMAGE=$DEMO_IMAGE_ID HASKOKI_DEMO_TEST_OUT=$_DI_DIR/compare timeout -s KILL 5400 bash scripts/test-demo-image.sh compare"
  _DI_STOPPED=""
  for _DI_P in contracts full compare; do
    if [ -n "$_DI_STOPPED" ]; then
      echo "phase $_DI_P: NOT RUN ($_DI_STOPPED rc=$DEMO_RC)" >>"$DEMO_LOG"
      continue
    fi
    run_demo_phase "$_DI_P" "$_DI_DIR/$_DI_P" "$_DI_DIR/$_DI_P.log" "$DEMO_IMAGE_ID" "$_DI_P"
    if [ "$DEMO_PHASE_RC" -ne 0 ]; then
      DEMO_RC=$DEMO_PHASE_RC
      _DI_STOPPED="$_DI_P"
    fi
  done
  if [ -z "$_DI_STOPPED" ]; then
    DEMO_RC=0
  fi
  echo "demo-image step: rc=$DEMO_RC" >>"$DEMO_LOG"
  return 0
}
# DEMO-PHASES-END

for d in $CONTAINER_DRIVERS; do
  LOG="$EVIDENCE_DIR/$d.log"
  echo "--- driver: $d"
  if [ "$d" = "test-proxy-parity.sh" ] && [ -n "${HASKOKI_PROXY_DIR:-}" ]; then
    [ -f "$HASKOKI_PROXY_DIR/pkcs11-proxy-ng" ] || fail "proxy dir lacks daemon: $HASKOKI_PROXY_DIR"
    CMD="timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host -v \$PWD:/work -w /work -v $HASKOKI_PROXY_DIR:/opt/pkcs11-proxy-ng:ro --env HASKOKI_PROXY_PORT=${HASKOKI_PROXY_PORT:-17512} $IMAGE scripts/$d"
    timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
      -v "$PWD:/work" -w /work \
      -v "$HASKOKI_PROXY_DIR:/opt/pkcs11-proxy-ng:ro" \
      --env HASKOKI_PROXY_PORT="${HASKOKI_PROXY_PORT:-17512}" \
      "$IMAGE" "scripts/$d" >"$LOG" 2>&1
    RC=$?
  else
    CMD="timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host -v \$PWD:/work -w /work $IMAGE scripts/$d"
    timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
      -v "$PWD:/work" -w /work \
      "$IMAGE" "scripts/$d" >"$LOG" 2>&1
    RC=$?
  fi
  record "$d" "$RC" "$LOG" "$CMD"
done

# ABI sensitivity control (T-1): the layout probes' headline property
# (hardcoded independent expectations) is proven, not just asserted.
# A leg of test-c-abi.sh, not a 16th driver: the inventory above is
# unaffected (no new test-*.sh).
echo "--- sensitivity leg: test-c-abi.sh --negative"
ABI_CMD="timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host -v \$PWD:/work -w /work $IMAGE scripts/test-c-abi.sh --negative"
timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
  -v "$PWD:/work" -w /work \
  "$IMAGE" scripts/test-c-abi.sh --negative >"$EVIDENCE_DIR/test-c-abi-negative.log" 2>&1
record "test-c-abi.sh --negative" "$?" "$EVIDENCE_DIR/test-c-abi-negative.log" "$ABI_CMD"

echo "--- release build: make-release.sh"
BUILD_CMD="timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host -v \$PWD:/work -w /work $IMAGE scripts/make-release.sh"
timeout -s KILL $DRIVER_TIMEOUT docker run --rm --network host \
  -v "$PWD:/work" -w /work \
  "$IMAGE" scripts/make-release.sh >"$EVIDENCE_DIR/make-release.sh.log" 2>&1
BUILD_RC=$?
record "make-release.sh" "$BUILD_RC" "$EVIDENCE_DIR/make-release.sh.log" "$BUILD_CMD"

# Stage one fresh tarball from the just-built bundle for the install
# leg. A stale archive at the old default path can never satisfy this:
# the path below is created fresh this run and passed explicitly.
# Staging diagnostics go to their own log: the build log was already
# hashed into its manifest line and must stay byte-identical to it.
STAGED="none"
ARCH_SHA="none"
TREE="none"
STAGE_LOG="$EVIDENCE_DIR/stage-archive.log"
if [ "$BUILD_RC" -ne 0 ]; then
  echo "staging skipped: bundle build failed (rc=$BUILD_RC)" >"$STAGE_LOG"
fi
if [ "$BUILD_RC" -eq 0 ]; then
  VER=$(grep -m1 '^version:' haskoki.cabal | awk '{print $2}')
  if [ -z "$VER" ]; then
    echo "cannot parse version from haskoki.cabal" >"$STAGE_LOG"
    BUILD_RC=1
  elif [ ! -f "dist-release/haskoki-$VER/lib/libhaskoki.so" ]; then
    echo "bundle tree incomplete after successful build: dist-release/haskoki-$VER" \
      >"$STAGE_LOG"
    BUILD_RC=1
  else
    TREE="dist-release/haskoki-$VER"
    STAGE_DIR="$EVIDENCE_DIR/staged"
    mkdir -p "$STAGE_DIR" || fail "cannot create $STAGE_DIR"
    STAGED="$STAGE_DIR/haskoki-$VER-linux-x86_64.tar.gz"
    if tar czf "$STAGED" -C dist-release "haskoki-$VER" \
        >"$STAGE_LOG" 2>&1 \
        && tar tzf "$STAGED" >/dev/null 2>&1; then
      ARCH_SHA=$(sha256sum "$STAGED" | awk '{print $1}')
      echo "staged fresh archive: $STAGED ($ARCH_SHA)" | tee -a "$STAGE_LOG"
    else
      echo "fresh-archive staging failed: $STAGED" >>"$STAGE_LOG"
      rm -f "$STAGED"
      STAGED="none"
      ARCH_SHA="none"
      BUILD_RC=1
    fi
  fi
fi
if [ "$BUILD_RC" -ne 0 ]; then
  # A post-build staging failure still blocks the dependent install;
  # the build line above already records the build's own exit status.
  STAGED="none"
  ARCH_SHA="none"
fi

# The install leg depends on the fresh bundle: exact staged paths in,
# never defaults. A bundle failure marks it BLOCKED (a miss overall)
# while independent host drivers below still produce evidence.
echo "--- host install test: test-release-install.sh"
INSTALL_LOG="$EVIDENCE_DIR/test-release-install.sh.log"
if [ "$BUILD_RC" -eq 0 ]; then
  TREE_ABS="$PWD/$TREE"
  INSTALL_CMD="HASKOKI_REQUIRE_EXPLICIT_ARGS=1 timeout -s KILL 900 bash scripts/test-release-install.sh $TREE_ABS $INSTALL_IMAGE $STAGED"
  HASKOKI_REQUIRE_EXPLICIT_ARGS=1 \
    timeout -s KILL 900 bash scripts/test-release-install.sh \
    "$TREE_ABS" "$INSTALL_IMAGE" "$STAGED" >"$INSTALL_LOG" 2>&1
  record "test-release-install.sh" "$?" "$INSTALL_LOG" "$INSTALL_CMD"
else
  INSTALL_CMD="bash scripts/test-release-install.sh <blocked: no fresh bundle>"
  echo "install blocked: bundle build/staging failed (see make-release.sh.log and stage-archive.log)" >"$INSTALL_LOG"
  record_blocked "test-release-install.sh" "$INSTALL_LOG" "$INSTALL_CMD" \
    "bundle build failed"
fi

for h in $HOST_DRIVERS; do
  if [ "$h" = "test-release-install.sh" ]; then
    continue
  fi
  case "$h" in
    test-demo-image.sh)
      echo "--- host demo-image driver: test-demo-image.sh (build + contracts/full/compare)"
      run_demo_image_phases "$EVIDENCE_DIR"
      record "test-demo-image.sh" "$DEMO_RC" "$DEMO_LOG" "$DEMO_CMD"
      ;;
    *)
      echo "--- host driver: $h"
      HOST_CMD="timeout -s KILL $DRIVER_TIMEOUT bash scripts/$h"
      timeout -s KILL $DRIVER_TIMEOUT bash "scripts/$h" >"$EVIDENCE_DIR/$h.log" 2>&1
      record "$h" "$?" "$EVIDENCE_DIR/$h.log" "$HOST_CMD"
      ;;
  esac
done

# Nested children run only inside their parent (never standalone here);
# informational lines, outside the pass/miss counts.
for n in $NESTED_DRIVERS; do
  NAME=${n%%:*}
  PARENT=${n#*:}
  RESULTS="$RESULTS$NAME NESTED parent=$PARENT (evidence inside parent log)
"
done

{
  echo "release evidence manifest"
  echo "stamp: $STAMP (utc)"
  echo "rev: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "image: $IMAGE"
  echo "image id: $IMAGE_ID"
  echo "install image: $INSTALL_IMAGE"
  echo "proxy dir: ${HASKOKI_PROXY_DIR:-<unset>}"
  echo "bundle tree: $TREE"
  echo "archive: $STAGED"
  echo "archive sha256: $ARCH_SHA"
  echo "pass: $PASS miss: $MISS blocked: $BLOCKED"
  printf '%s' "$RESULTS"
} >"$EVIDENCE_DIR/MANIFEST.txt"
cat "$EVIDENCE_DIR/MANIFEST.txt"

if [ "$MISS" -ne 0 ]; then
  fail "$MISS of $((PASS + MISS)) evidence steps missed"
fi
echo "PASS: release-evidence.sh ($PASS/$((PASS + MISS)) steps passing)"
