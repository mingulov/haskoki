#!/bin/sh
# scripts/test-demo-image.sh -- demo image end-to-end driver (host side).
#
# Builds the self-contained demo image, then proves every entrypoint
# contract: expected tag/digest shape, demo verifications, check lanes
# (smoke/full x direct/proxy, all under --network none; direct
# byte-exact, proxy stable-core strict), compare diff
# (under --network none; frozen R9 parity subset: 83 exclusions,
# strict — no flaky variance allowance) + the shipped
# compare-classify wrapper leg (in-image ok + drift controls),
# help texts + usage-error matrix + examples (incl. proxy-example
# 5/5) + JSON purity, arbitrary-UID rerun,
# --network none demo rerun (loopback proxy stays up), glibc floor over
# bundle + proxy + venv ELF, and records the image digest plus a layer
# note on reproducibility.
#
# Usage (from repo root):
#   scripts/test-demo-image.sh
# Env:
#   HASKOKI_DEMO_TEST_OUT   host out dir (default mktemp; bind-mounted
#                           to /out; made world-writable for the UID leg)
#   HASKOKI_DEMO_STEP_TIMEOUT
#                           per-step timeout seconds (default 7200; each
#                           full lane takes tens of minutes and compare
#                           runs two of them back to back)
#   HASKOKI_DEMO_REVISION   source SHA baked into the revision label
#                           (default unset: revision=unknown; lane
#                           behavior identical either way)
#   HASKOKI_DEMO_USE_STAGED consume ./dist-release/haskoki-<ver> as the
#                           staged bundle WITHOUT rebuilding (CI: the
#                           release-bundle artifact lands there; default
#                           unset: the driver builds it fresh via
#                           make-release.sh in the toolchain container)
#
# Exit status: 0 iff every leg holds; any deviation fails loudly.
# Never pushes or tags anything beyond the local test tag.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() { echo "FAIL: $1"; exit 1; }
note() { echo "--- $1"; }

command -v docker >/dev/null 2>&1 || fail "docker missing"
command -v timeout >/dev/null 2>&1 || fail "timeout missing"

VER=$(grep -m1 '^version:' haskoki.cabal | awk '{print $2}')
[ -n "$VER" ] || fail "cannot parse version from haskoki.cabal"
TAG="haskoki-demo:$VER"
STEP_TIMEOUT="${HASKOKI_DEMO_STEP_TIMEOUT:-7200}"

if [ -n "${HASKOKI_DEMO_TEST_OUT:-}" ]; then
  OUT="$HASKOKI_DEMO_TEST_OUT"
  mkdir -p "$OUT" || fail "cannot create $OUT"
else
  OUT=$(mktemp -d /tmp/haskoki-demo-test.XXXXXX) || fail "mktemp failed"
fi
chmod 777 "$OUT" || fail "cannot chmod $OUT"
echo "host out dir: $OUT"

# Latest run dir for a command tag (unique per invocation by design).
latest_run() {
  # $1 = tag prefix (demo, check-*, compare, uri-demo)
  ls -dt "$OUT"/$1-* 2>/dev/null | head -1
}

# Strict byte-exact set assertion (R5 section 4: the v0.2.2 freeze
# classifies every id as stable-eligible, so ZERO flaky variants are
# allowed — any variance fails loud and re-opens section 4 with
# current-pin evidence; the R3d allowance it replaces is recorded in
# task-R3-report.md section 9.8).
# $1 = label, $2 = expected file, $3 = actual file. No $4.. accepted.
# Passes iff actual == expected line-for-line, compared BYTE-exact
# (line terminators included: CRLF or a missing final LF fails);
# anything else — a missing line, an unexpected line — fails loudly
# with a diff.
check_stable_core() {
  label="$1"; exp="$2"; act="$3"; shift 3
  [ $# -eq 0 ] || fail "$label: check_stable_core takes no variant args (R5 strict)"
  python3 - "$label" "$exp" "$act" <<'PY' || fail "$label differs from the frozen stable set"
import difflib, sys
label, exp, act = sys.argv[1], sys.argv[2], sys.argv[3]
raw_exp = open(exp, "rb").read()
raw_act = open(act, "rb").read()
try:
    want = raw_exp.decode("utf-8").splitlines()
    got = raw_act.decode("utf-8").splitlines()
except UnicodeDecodeError as e:
    print("%s: non-UTF8 bytes: %s" % (label, e))
    sys.exit(1)
if got != want:
    print("%s: stable set differs:" % label)
    for l in difflib.unified_diff(want, got, "expected-stable",
                                  "actual", lineterm=""):
        print(l)
    sys.exit(1)
# Byte-exactness: the entrypoint writes LF-terminated lines, so the
# raw bytes must equal the parsed lines rejoined with LF. Any CR,
# missing final LF, or blank-line smuggling fails here.
canon_act = ("\n".join(got) + "\n").encode("utf-8") if got else b""
if raw_act != canon_act:
    print("%s: bytes differ though lines match (CR? missing final LF? blank line?)" % label)
    sys.exit(1)
canon_exp = ("\n".join(want) + "\n").encode("utf-8") if want else b""
if raw_exp != canon_exp:
    print("%s: expected file itself is not LF-canonical" % label)
    sys.exit(1)
print("%s: stable set holds (%d lines, byte-exact, zero variants allowed)" % (
    label, len(want)))
PY
}

# ---------------------------------------------------------------------------
# 0. Stage the bundle (R8/D1: the image is built FROM this tree).
# ---------------------------------------------------------------------------
STAGED_SRC="dist-release/haskoki-$VER"
if [ -n "${HASKOKI_DEMO_USE_STAGED:-}" ]; then
  note "using staged bundle $STAGED_SRC (CI artifact, not rebuilt)"
  [ -f "$STAGED_SRC/lib/libhaskoki.so" ] \
    || fail "staged bundle missing lib: $STAGED_SRC (release-bundle artifact not extracted?)"
  [ -x "$STAGED_SRC/bin/haskoki-ctl" ] \
    || fail "staged bundle missing executable ctl: $STAGED_SRC"
  [ -f "$STAGED_SRC/toolchain-record.txt" ] \
    || fail "staged bundle missing toolchain record: $STAGED_SRC"
else
  note "staging bundle via make-release.sh"
  docker inspect haskoki-dev:ghc-9.10.3 >/dev/null 2>&1 \
    || fail "builder image missing (run: docker build -t haskoki-dev:ghc-9.10.3 .)"
  docker run --rm --network host -v "$PWD:/work" -w /work \
    haskoki-dev:ghc-9.10.3 scripts/make-release.sh > "$OUT/stage-bundle.log" 2>&1 \
    || fail "bundle staging failed (see $OUT/stage-bundle.log)"
  tail -2 "$OUT/stage-bundle.log"
  [ -f "$STAGED_SRC/lib/libhaskoki.so" ] \
    || fail "staged bundle missing lib after build: $STAGED_SRC"
fi
STAGED_SHA=$(sha256sum "$STAGED_SRC/lib/libhaskoki.so" | awk '{print $1}')
echo "staged bundle: $STAGED_SRC (libhaskoki sha256 $STAGED_SHA)"
# Exact tree the Dockerfile COPYs (nothing else from dist-release/
# may leak into the image: no archives, no manifest, no results).
rm -rf staged-bundle
mkdir -p staged-bundle || fail "cannot create staged-bundle/"
cp -a "$STAGED_SRC" staged-bundle/ || fail "cannot copy staged bundle"
test -x "staged-bundle/haskoki-$VER/bin/haskoki-ctl" \
  || fail "staged copy lost the executable bit"

# ---------------------------------------------------------------------------
# 1. Build image, assert tag/digest shape.
# ---------------------------------------------------------------------------
note "build image $TAG"
# Optional label input (R8 staged-only identity): when set, the
# source SHA is baked into the revision label; unset builds
# exactly as before (revision=unknown). No lane behavior changes.
if [ -n "${HASKOKI_DEMO_REVISION:-}" ]; then
  BUILD_CMD="docker build -f docker/Dockerfile.demo --build-arg REVISION=$HASKOKI_DEMO_REVISION -t $TAG ."
else
  BUILD_CMD="docker build -f docker/Dockerfile.demo -t $TAG ."
fi
echo "build command: $BUILD_CMD"
if [ -n "${HASKOKI_DEMO_REVISION:-}" ]; then
  docker build -f docker/Dockerfile.demo \
    --build-arg "REVISION=$HASKOKI_DEMO_REVISION" -t "$TAG" . \
    > "$OUT/build.log" 2>&1 \
    || fail "image build failed (see $OUT/build.log)"
else
  docker build -f docker/Dockerfile.demo -t "$TAG" . > "$OUT/build.log" 2>&1 \
    || fail "image build failed (see $OUT/build.log)"
fi
tail -3 "$OUT/build.log"

IMGID=$(docker inspect --format '{{.Id}}' "$TAG" 2>/dev/null) \
  || fail "cannot inspect $TAG"
echo "$IMGID" | grep -qE '^sha256:[0-9a-f]{64}$' \
  || fail "image id has unexpected shape: $IMGID"
IMGSIZE=$(docker inspect --format '{{.Size}}' "$TAG")
echo "image id: $IMGID"
echo "image size: $IMGSIZE bytes"
# The image holds the staged bytes now; remove the context copy so a
# stale tree can never leak into a later build (the source tree stays
# in dist-release/ for inspection).
rm -rf staged-bundle
echo "staged-bundle/ context copy removed"
REPO_DIGESTS=$(docker inspect --format '{{.RepoDigests}}' "$TAG")
echo "repo digests: $REPO_DIGESTS (local build; nothing pushed)"
BUILDER_ID=$(docker inspect --format '{{.Id}}' haskoki-dev:ghc-9.10.3 2>/dev/null || echo unknown)
echo "builder image id: $BUILDER_ID"

# ---------------------------------------------------------------------------
# 2. demo: exit 0 + report markers.
# ---------------------------------------------------------------------------
note "demo (expect exit 0)"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm -v "$OUT:/out" "$TAG" demo \
  > "$OUT/demo.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "demo exited $rc, want 0 (see $OUT/demo.log)"
grep -q 'demo-ok: 8/8 verifications hold' "$OUT/demo.log" \
  || fail "demo summary marker missing"
DEMO_RUN=$(latest_run demo)
[ -n "$DEMO_RUN" ] && [ -f "$DEMO_RUN/report.json" ] \
  || fail "demo report.json missing under $OUT"
python3 - "$DEMO_RUN/report.json" <<'PY' || fail "demo report.json malformed"
import json, sys
r = json.load(open(sys.argv[1]))
assert r["command"] == "demo", r
assert r["exit_code"] == 0, r
assert len(r["steps"]) == 8, r
PY
echo "demo: 8/8 verifications, report at $DEMO_RUN/report.json"

# ---------------------------------------------------------------------------
# 3. check lanes: exact outcomes per mode/profile.
# ---------------------------------------------------------------------------
run_check() {
  # $1 = mode, $2 = profile, $3 = want exit
  # All lanes run with --network none (plan section 7.1: runtime
  # scenarios need no external network; the loopback proxy is
  # unaffected). A hidden network fetch would fail loudly here.
  note "check --mode $1 --profile $2 (expect exit $3)"
  timeout -s KILL "$STEP_TIMEOUT" \
    docker run --rm --network none -v "$OUT:/out" "$TAG" \
      check --mode "$1" --profile "$2" > "$OUT/check-$1-$2.log" 2>&1
  rc=$?
  [ "$rc" -eq "$3" ] || fail "check $1/$2 exited $rc, want $3"
  RUN_DIR=$(latest_run "check-$1-$2")
  [ -n "$RUN_DIR" ] && [ -f "$RUN_DIR/report.json" ] \
    || fail "check $1/$2 report.json missing"
  echo "check $1/$2: exit $rc, run at $RUN_DIR"
}

run_check direct smoke 0
grep -q 'findings: none' "$OUT/check-direct-smoke.log" \
  || fail "smoke/direct summary marker missing"
run_check proxy smoke 0
grep -q 'findings: none' "$OUT/check-proxy-smoke.log" \
  || fail "smoke/proxy summary marker missing"

# Full lanes exit 1 with exact finding sets (R9 on proxy v0.2.2: 27
# direct / 27 proxy-core / diff-core + shared re-frozen below on
# checker 0.2.3; triaged in task-R9-report.md). Direct is byte-exact
# (deterministic across runs; identical set to R4 — backend unchanged).
# Proxy asserts a stable 27-line core exactly (strict, codex I4 —
# the failed pair's historical {pass, fail} bound is NOT suppressed);
# any other line fails loudly. R9 delta vs R5: +2 GMAC message-init
# lines (init params now forward; the backend's native 0x7 refusal
# surfaces byte-identical in both lanes, verified in the run dirs).
run_check direct full 1
RUN_DIR=$(latest_run "check-direct-full")
cat > "$OUT/exp-full-direct.txt" <<'EOF'
failed ckr/test_ckr_v32_raw.py::TestAsyncErrors::test_async_get_id_empty_selector
failed ckr/test_ckr_v32_raw.py::TestAsyncErrors::test_async_get_id_no_operation
failed test_mech_message.py::TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback
failed test_mech_message.py::TestMessageEncrypt::test_message_encrypt_decrypt_aes_gcm
failed test_mech_message.py::TestMessageEncrypt::test_message_encrypt_multipart_aes_gcm
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[AES_GCM]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[AES_GCM]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[AES_GMAC]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[HOTP]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[AES_GMAC]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[HOTP]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
EOF
[ "$(wc -l < "$OUT/exp-full-direct.txt")" -eq 27 ] || fail "driver: want 27 expected direct findings"
if ! diff -u "$OUT/exp-full-direct.txt" "$RUN_DIR/findings.txt"; then
  fail "check direct/full findings differ from the exact expected 27"
fi
echo "check direct/full: exact 27 findings match"

run_check proxy full 1
RUN_DIR=$(latest_run "check-proxy-full")
cat > "$OUT/exp-full-proxy.txt" <<'EOF'
failed ckr/test_ckr_v32_raw.py::TestAsyncErrors::test_async_get_id_empty_selector
failed ckr/test_ckr_v32_raw.py::TestAsyncErrors::test_async_get_id_no_operation
failed test_mech_message.py::TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback
failed test_mech_message.py::TestMessageEncrypt::test_message_encrypt_decrypt_aes_gcm
failed test_mech_message.py::TestMessageEncrypt::test_message_encrypt_multipart_aes_gcm
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[AES_GCM]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[AES_GCM]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[AES_GMAC]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[HOTP]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[AES_GMAC]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[HOTP]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
EOF
[ "$(wc -l < "$OUT/exp-full-proxy.txt")" -eq 27 ] || fail "driver: want 27 stable-core proxy findings"
# R5 strict (codex I4): the failed pair's {pass, fail} bound is
# historical (older pin) — v0.2.0 never demonstrated the flip, so
# no failure form is suppressed here; any variance fails loud and
# re-opens §4 with current-pin evidence.
check_stable_core "check proxy/full findings" "$OUT/exp-full-proxy.txt" \
  "$RUN_DIR/findings.txt"

# ---------------------------------------------------------------------------
# 4. compare: exit 1 with a stable-core diff + exact shared set.
# R9 parity-subset re-freeze (proxy v0.2.2): the diff asserts the
# 83-line exclusion core exactly (6 families: message-init 0x71
# x34, blowfish catalog x20, tls12-derive x2, wtls-premaster x3,
# boundary-order x2, proxy-better inversions x22 — every delta
# vs R5 caused in task-R9-report.md section 4; GMAC moved to
# shared); the 27-line shared set stays byte-exact.
# Parity-eligible = every other collected id (default-eligible;
# the freeze is this exclusion list, not an 11k allowlist). Flaky
# ids assert their measured v0.2.2 verdicts with NO variance
# allowance (strict, codex I4 — historical bounds in R5 §4 would
# mask a pin regression if suppressed).
# ---------------------------------------------------------------------------
note "compare (expect exit 1 with exact diff)"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --network none -v "$OUT:/out" "$TAG" \
  compare > "$OUT/compare.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "compare exited $rc, want 1"
RUN_DIR=$(latest_run compare)
[ -n "$RUN_DIR" ] && [ -f "$RUN_DIR/report.json" ] \
  || fail "compare report.json missing"
# Single-source freeze data (codex I3): the shipped in-image wrapper
# `examples/release/compare-classify` reads these same files, so the
# driver and the classifier cannot drift apart.
CC_DATA="examples/release/compare-classify"
[ -f "$CC_DATA/frozen-subset.tsv" ] || fail "missing $CC_DATA/frozen-subset.tsv"
[ -f "$CC_DATA/frozen-shared.txt" ] || fail "missing $CC_DATA/frozen-shared.txt"
python3 - "$CC_DATA/frozen-subset.tsv" <<'PY' || fail "frozen-subset.tsv tallies drifted"
import sys
from collections import Counter
rows = [l for l in open(sys.argv[1]).read().splitlines()
        if l and not l.startswith("#")]
c = Counter(l.split("\t", 1)[0] for l in rows)
want = {"A-msg-init-0x71": 34, "B-blowfish": 20, "C-tls12": 2,
        "D-wtls": 3, "E-boundary": 2, "G-inversion": 22}
assert len(rows) == 83 and dict(c) == want, (len(rows), dict(c))
PY
grep -v '^#' "$CC_DATA/frozen-subset.tsv" | cut -f2- > "$OUT/exp-diff.txt"
grep -v '^#' "$CC_DATA/frozen-shared.txt" > "$OUT/exp-shared.txt"
[ "$(wc -l < "$OUT/exp-diff.txt")" -eq 83 ] || fail "driver: want 83 stable-core diff lines"
# R9 strict (codex I4): flaky bounds are historical (older pin) —
# v0.2.2 measured no flips, so the freeze asserts the measured
# verdicts exactly; any variance fails loud and re-opens §4.
check_stable_core "compare diff" "$OUT/exp-diff.txt" "$RUN_DIR/diff.txt"
if ! diff -u "$OUT/exp-shared.txt" "$RUN_DIR/shared-findings.txt"; then
  fail "compare shared set differs from the exact expected set"
fi
echo "compare: stable-core diff + exact shared set match"

# Subset-aware wrapper (codex I3): exercise the SHIPPED in-image
# classifier on this compare run dir (raw plumbing stays untouched),
# then prove its drift sensitivity in both directions on copies.
note "compare-classify wrapper (expect exit 0 + drift controls exit 1)"
CC_RUN=$(basename "$RUN_DIR")
timeout -s KILL 300 docker run --rm --network none -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" \
  /opt/haskoki/examples/release/compare-classify/compare-classify \
  "/out/$CC_RUN" > "$OUT/classify.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "in-image compare-classify exited $rc, want 0"
grep -q 'compare-classify-ok: 83 known-difference + shared 27/27 exact' \
  "$OUT/classify.log" || fail "compare-classify ok marker missing"
[ -f "$RUN_DIR/classification.json" ] || fail "classification.json missing"
python3 - "$RUN_DIR/classification.json" <<'PY' || fail "classification.json counts drifted"
import json, sys
c = json.load(open(sys.argv[1]))["counts"]
assert c == {"known_difference": 83, "direct_only": 0, "flaky": 0,
             "unexpected_difference": 0, "missing_known": 0,
             "duplicate_diff_lines": 0, "shared_expected": 27,
             "shared_actual": 27, "shared_exact": True}, c
PY
# Drift controls on run-dir copies (the raw run dir is untouched):
# an injected line must surface as unexpected=1, a removed frozen
# line as missing-known=1 — each exiting 1.
rm -rf "$OUT/cc-inject" "$OUT/cc-remove"
mkdir -p "$OUT/cc-inject" "$OUT/cc-remove"
cp "$RUN_DIR/diff.txt" "$RUN_DIR/shared-findings.txt" "$OUT/cc-inject/"
cp "$RUN_DIR/diff.txt" "$RUN_DIR/shared-findings.txt" "$OUT/cc-remove/"
echo 'passed failed INJECTED::drift-control' >> "$OUT/cc-inject/diff.txt"
head -n -1 "$RUN_DIR/diff.txt" > "$OUT/cc-remove/diff.txt"
timeout -s KILL 300 docker run --rm --network none -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" \
  /opt/haskoki/examples/release/compare-classify/compare-classify \
  /out/cc-inject > "$OUT/classify-inject.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "classify injection control exited $rc, want 1"
grep -q 'unexpected 1' "$OUT/classify-inject.log" \
  || fail "injection control marker missing"
timeout -s KILL 300 docker run --rm --network none -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" \
  /opt/haskoki/examples/release/compare-classify/compare-classify \
  /out/cc-remove > "$OUT/classify-remove.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "classify removal control exited $rc, want 1"
grep -q 'missing-known 1' "$OUT/classify-remove.log" \
  || fail "removal control marker missing"
echo "compare-classify: in-image ok + injection/removal controls hold"

# ---------------------------------------------------------------------------
# 5. Help/exit matrix, examples, JSON purity (fast legs).
# ---------------------------------------------------------------------------
note "help texts (expect exit 0)"
timeout -s KILL 120 docker run --rm "$TAG" --help > "$OUT/help-top.log" 2>&1 \
  || fail "--help failed"
grep -q 'Exit codes (exact)' "$OUT/help-top.log" || fail "top help marker missing"
for c in demo check compare; do
  timeout -s KILL 120 docker run --rm "$TAG" "$c" --help > "$OUT/help-$c.log" 2>&1 \
    || fail "$c --help failed"
done
grep -q 'fixed-fixture' "$OUT/help-demo.log" || fail "demo help marker missing"
grep -q 'FROZEN (R4' "$OUT/help-check.log" || fail "check help marker missing"
grep -q 'frozen parity subset (R5' "$OUT/help-compare.log" || fail "compare help marker missing"
echo "help texts: 4/4 exit 0"

note "usage-error matrix (expect exit 2 x8)"
i=0
expect2() {
  # "$@" = argv; asserts exit 2 and non-empty stderr (usage text).
  i=$((i + 1))
  timeout -s KILL 120 docker run --rm "$TAG" "$@" \
    > "$OUT/bad-$i.out" 2> "$OUT/bad-$i.err"
  rc=$?
  [ "$rc" -eq 2 ] || fail "bad case $i ($*) exited $rc, want 2"
  [ -s "$OUT/bad-$i.err" ] || fail "bad case $i ($*) has empty stderr"
}
expect2 frobnicate
expect2 check
expect2 check --mode direct
expect2 check --profile smoke
expect2 check --mode bogus --profile smoke
expect2 check --mode direct --profile bogus
expect2 --output bogus demo
expect2 demo --bogus-flag
echo "usage errors: 8/8 exit 2"

note "examples (executable + runnable in-image)"
[ -x examples/release/check-smoke ] || fail "check-smoke not executable"
[ -x examples/release/pkcs11-uri-demo ] || fail "pkcs11-uri-demo not executable"
[ -x examples/release/proxy-example ] || fail "proxy-example not executable"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" /opt/haskoki/examples/release/check-smoke \
  > "$OUT/ex-smoke-direct.log" 2>&1
[ $? -eq 0 ] || fail "check-smoke direct failed"
grep -q 'findings: none' "$OUT/ex-smoke-direct.log" \
  || fail "check-smoke direct marker missing"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" /opt/haskoki/examples/release/check-smoke --mode proxy \
  > "$OUT/ex-smoke-proxy.log" 2>&1
[ $? -eq 0 ] || fail "check-smoke proxy failed"
grep -q 'findings: none' "$OUT/ex-smoke-proxy.log" \
  || fail "check-smoke proxy marker missing"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" /opt/haskoki/examples/release/pkcs11-uri-demo \
  > "$OUT/ex-uri.log" 2>&1
[ $? -eq 0 ] || fail "pkcs11-uri-demo failed"
grep -q 'uri-demo-ok' "$OUT/ex-uri.log" || fail "uri-demo marker missing"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm -v "$OUT:/out" \
  --entrypoint /bin/sh "$TAG" /opt/haskoki/examples/release/proxy-example \
  > "$OUT/ex-proxy.log" 2>&1
[ $? -eq 0 ] || fail "proxy-example failed"
grep -q 'proxy-example-ok: 5/5 steps hold' "$OUT/ex-proxy.log" \
  || fail "proxy-example marker missing"
echo "examples: check-smoke x2 + uri-demo + proxy-example hold"

note "JSON purity (--output json demo)"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm -v "$OUT:/out" "$TAG" \
  --output json demo > "$OUT/json-demo.out" 2> "$OUT/json-demo.err"
[ $? -eq 0 ] || fail "json demo failed"
JR=$(latest_run demo)
python3 - "$OUT/json-demo.out" "$JR/report.json" <<'PY' || fail "json demo stdout is not the report document"
import json, sys
stdout_doc = json.load(open(sys.argv[1]))
file_doc = json.load(open(sys.argv[2]))
assert stdout_doc == file_doc, "stdout JSON differs from report.json"
assert stdout_doc["command"] == "demo" and stdout_doc["exit_code"] == 0
assert len(stdout_doc["steps"]) == 8
PY
echo "JSON purity: stdout is exactly the report document"

# ---------------------------------------------------------------------------
# 6. Arbitrary-UID rerun (no passwd entry, no HOME).
# ---------------------------------------------------------------------------
note "arbitrary UID rerun (19876:19876)"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --user 19876:19876 \
  -v "$OUT:/out" "$TAG" demo > "$OUT/uid-demo.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "UID demo exited $rc, want 0"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --user 19876:19876 \
  -v "$OUT:/out" "$TAG" check --mode direct --profile smoke \
  > "$OUT/uid-smoke.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "UID smoke exited $rc, want 0"
echo "arbitrary UID: demo + smoke/direct hold"

# ---------------------------------------------------------------------------
# 7. --network none rerun (loopback proxy stays up).
# ---------------------------------------------------------------------------
note "--network none rerun"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --network none \
  -v "$OUT:/out" "$TAG" demo > "$OUT/nonet-demo.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "nonet demo exited $rc, want 0"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --network none \
  -v "$OUT:/out" "$TAG" check --mode direct --profile smoke \
  > "$OUT/nonet-smoke-direct.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "nonet smoke/direct exited $rc, want 0"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --network none \
  -v "$OUT:/out" "$TAG" check --mode proxy --profile smoke \
  > "$OUT/nonet-smoke-proxy.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "nonet smoke/proxy exited $rc, want 0"
echo "--network none: demo + smoke/direct + smoke/proxy hold"

# ---------------------------------------------------------------------------
# 8. glibc floor over shipped ELF (extracted from the image, read-only).
# Covers the bundle tree AND the shipped proxy pair AND the checker
# venv's native extensions (all user-visible ELF in the image).
# ---------------------------------------------------------------------------
note "glibc floor over shipped ELF"
SCAN=$(mktemp -d /tmp/haskoki-demo-scan.XXXXXX) || fail "mktemp failed"
CID=$(docker create "$TAG" demo) || fail "docker create failed"
docker cp "$CID:/opt/haskoki/dist-release/." "$SCAN/" > /dev/null \
  || fail "docker cp of bundle failed"
docker cp "$CID:/opt/haskoki/proxy/." "$SCAN/proxy/" > /dev/null \
  || fail "docker cp of proxy pair failed"
docker cp "$CID:/opt/p11c/." "$SCAN/p11c/" > /dev/null \
  || fail "docker cp of checker venv failed"
docker rm "$CID" > /dev/null
ARTD=$(echo "$SCAN"/haskoki-*)
[ -d "$ARTD" ] || fail "no bundle tree extracted"
[ -f "$SCAN/proxy/pkcs11-proxy-ng" ] || fail "no proxy daemon extracted"
[ -d "$SCAN/p11c" ] || fail "no checker venv extracted"
list_bundle_elfs() {
  for f in "$ARTD"/lib/*.so "$ARTD"/lib/*.so.* \
      "$ARTD"/lib/ossl-modules/*.so "$ARTD"/bin/haskoki-ctl; do
    [ -f "$f" ] && echo "$f"
  done
}
list_proxy_elfs() {
  for f in "$SCAN"/proxy/pkcs11-proxy-ng "$SCAN"/proxy/*.so; do
    [ -f "$f" ] && echo "$f"
  done
}
list_venv_elfs() { find "$SCAN/p11c" -name '*.so*' -type f; }
max_of() {
  while IFS= read -r f; do
    objdump -T "$f" 2>/dev/null | grep -o "GLIBC_[0-9.]*"
  done | sort -uV | tail -1
}
if command -v objdump >/dev/null 2>&1; then
  BUNDLE_FLOOR=$(list_bundle_elfs | max_of)
  PROXY_FLOOR=$(list_proxy_elfs | max_of)
  VENV_FLOOR=$(list_venv_elfs | max_of)
  FLOOR=$(printf '%s\n%s\n%s\n' "$BUNDLE_FLOOR" "$PROXY_FLOOR" "$VENV_FLOOR" | sort -uV | tail -1)
  N_BUNDLE=$(list_bundle_elfs | wc -l)
  N_PROXY=$(list_proxy_elfs | wc -l)
  N_VENV=$(list_venv_elfs | wc -l)
  echo "group maxima: bundle $BUNDLE_FLOOR ($N_BUNDLE ELFs), proxy $PROXY_FLOOR ($N_PROXY ELFs), venv $VENV_FLOOR ($N_VENV ELFs)"
else
  # Fallback: builder image carries binutils (read-only scan of the
  # extracted tree via bind mount; the demo image stays slim).
  FLOOR=$(docker run --rm -v "$SCAN:/scan:ro" haskoki-dev:ghc-9.10.3 \
    sh -c '{ for f in /scan/haskoki-*/lib/*.so /scan/haskoki-*/lib/*.so.* /scan/haskoki-*/lib/ossl-modules/*.so /scan/haskoki-*/bin/haskoki-ctl /scan/proxy/pkcs11-proxy-ng /scan/proxy/*.so; do [ -f "$f" ] || continue; objdump -T "$f" 2>/dev/null | grep -o "GLIBC_[0-9.]*"; done; find /scan/p11c -name "*.so*" -type f | while IFS= read -r f; do objdump -T "$f" 2>/dev/null | grep -o "GLIBC_[0-9.]*"; done; } | sort -uV | tail -1')
fi
echo "measured floor: $FLOOR (want GLIBC_2.43)"
[ "$FLOOR" = "GLIBC_2.43" ] || fail "glibc floor moved: $FLOOR"
echo "floor holds: $FLOOR over bundle + proxy + venv native extensions"

# ---------------------------------------------------------------------------
# 9. Record digest + layer note.
# ---------------------------------------------------------------------------
note "record"
{
  echo "image: $TAG"
  echo "id: $IMGID"
  echo "size: $IMGSIZE bytes"
  echo "builder: $BUILDER_ID"
  echo "build: $BUILD_CMD (from repo root)"
  echo "glibc floor: $FLOOR"
  echo "layers:"
  docker history --no-trunc --format '{{.Size}} {{.CreatedBy}}' "$TAG" \
    | head -40 | sed 's/^/  /'
} | tee "$OUT/image-record.txt"
cat > "$OUT/reproducibility-note.txt" <<'EOF'
Reproducibility note (demo image): rebuilds from the same inputs are
NOT bit-reproducible, so a rebuilt image id is expected to differ.
Concrete nondeterminism sources: file mtimes across stages, Python
bytecode caches in the checker venv, floating apt/PyPI/crates snapshots
behind the pinned names, and registry tag drift on ubuntu:26.04 (only
rust:1.94-bookworm is recipe-pinned, and tags still float). What IS
pinned and re-verified per build: the bundle recipe gates (static
libcrypto, provider origin, system-only host deps, GLIBC_2.43 floor),
the proxy canonical pair for the default ref (byte-identical assertion
in the proxy stage), pkcs11-check == 0.2.3 (venv + version assertion),
and every entrypoint verdict asserted byte-exact on its stable core by
this driver. Four proxy-lane timing-flaky test ids carry historical
bounds (R5 report section 4; a fifth id is transcript-stable) but
no variance allowance on this pin — any line outside the stable
core fails the driver loudly. The parity subset is frozen (R9):
83 compare exclusions in 6 reasoned families, strict.
Functional reproducibility = same versions + same outcomes above.
EOF
cat "$OUT/reproducibility-note.txt"

echo "PASS: test-demo-image.sh (demo + check x4 + compare + help/matrix/examples/json + UID + nonet + floor)"
