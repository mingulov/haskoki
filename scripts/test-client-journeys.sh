#!/bin/sh
# Installed-client journey driver.
#
# Executes the required legs of tests/journeys/legs.json against an
# installed bundle (never a source-tree build) and writes one
# machine-checked record per leg plus a summary. The Python engine
# (tests/journeys/journeys.py run) performs leg execution; this script
# enforces the installed-only contract and owns the output root.
#
# Installed-only contract (checked before any leg runs; each refusal
# exits 2 as "JOURNEY-SETUP: <reason>"):
# - --module is absolute and names an existing file;
# - its canonical path is outside the runner checkout (the enclosing
#   git worktree when git is present, else the source root holding this
#   script) and contains no dist-newstyle path component;
# - the bundle prefix (the parent of the directory holding the module)
#   carries toolchain-record.txt, closure/review.txt and an executable
#   bin/haskoki-ctl;
# - LD_LIBRARY_PATH, LD_PRELOAD and HASKOKI_CONFIG are unset in the
#   caller; every leg receives its own explicit HASKOKI_CONFIG;
# - --out names a new absolute directory outside the checkout; the
#   runner creates and owns it;
# - --module and --bundle-tar are exclusive; the tarball installs fresh
#   under <out>/prefix and must hold exactly one
#   haskoki-*/lib/libhaskoki.so.
#
# Profiles:
# - portfolio: the installed bundle plus pinned clients (OpenSC,
#   GnuTLS, Java, openssl) in a disposable container;
# - image: the candidate demo image (OpenSC and native legs in the
#   image, verifier legs on the host).
#
# Client container recipe (portfolio): start from ubuntu:26.04 with
# host networking for package retrieval, install the pinned client
# packages (opensc, gnutls-bin, default-jdk-headless, openssl) plus
# python3 and the bundle runtime libraries, mount the checkout
# read-only at /src, stage the bundle tarball and the host-built
# native fixtures under the evidence volume, then invoke this script
# with --bundle-tar and an --out under that volume. The image profile
# runs its module phase inside the candidate image with no network and
# its verifier phase on the host.
#
# Phases: module legs need the installed module; verifier legs run
# independent checks (openssl, JDK) over saved outputs. A portfolio
# run executes both phases in one container invocation. An image run
# executes the module phase in the image (--phase module --out ...),
# then the verifier phase on the host (--phase verifier
# --out-existing ...), which appends verifier records, recomputes the
# time to first verified signature over the merged run, and judges the
# aggregate. A module-only run writes a partial summary and skips the
# aggregate judgement.
#
# A leg that cannot run or that misses its expectations still writes
# its record, its combined log and its substituted config; the
# aggregate judges every required leg and fails on any missing leg,
# setup problem, wrong exit, absent marker, unreachable refusal,
# failed verifier, changed bytes, or version drift.
#
# Usage:
#   scripts/test-client-journeys.sh --profile portfolio|image --out ABS_NEW_DIR \
#     (--bundle-tar ABS_FILE | --module ABS_FILE) --native-dir ABS_DIR \
#     [--phase all|module] [--artifact-image IMAGE_ID]
#     [--source-sha SHA --source-dirty true|false]
#     [--client-setup-seconds N] [--legs ABS_FILE]
#   scripts/test-client-journeys.sh --profile P --phase verifier \
#     --out-existing ABS_RUN_DIR [--legs ABS_FILE]
#   scripts/test-client-journeys.sh --check ABS_RUN_DIR --profile P \
#     [--legs ABS_FILE]
#   scripts/test-client-journeys.sh --build-native ABS_NEW_DIR
#   scripts/test-client-journeys.sh --self-test
#
# --legs selects an alternate required-leg table; it exists for the
# build-free control suite and defaults to the committed table. Exit
# codes: 0 when the aggregate passes; 1 when the aggregate fails; 2 on
# a setup refusal ("JOURNEY-SETUP: <reason>").
set -eu

refuse() {
    printf 'JOURNEY-SETUP: %s\n' "$1" >&2
    return 2
}

canonical() {
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$1"
    else
        python3 -I -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
    fi
}

find_src_root() {
    if [ -f "tests/journeys/journeys.py" ]; then
        pwd -P
        return 0
    fi
    case "${0-}" in
        *"/"*)
            _d=$(dirname -- "$0")
            if [ -f "$_d/../tests/journeys/journeys.py" ]; then
                (CDPATH= cd -- "$_d/.." && pwd -P)
                return 0
            fi
            ;;
    esac
    printf 'JOURNEY-SETUP: source root not found\n' >&2
    return 2
}

find_checkout() {
    _src=$(find_src_root) || return 2
    if command -v git >/dev/null 2>&1; then
        if _top=$(git -C "$_src" rev-parse --show-toplevel 2>/dev/null); then
            printf '%s\n' "$_top"
            return 0
        fi
    fi
    printf '%s\n' "$_src"
}

is_inside() {
    _p=$(canonical "$1")
    _r=$(canonical "$2")
    case "$_p" in
        "$_r"/*) return 0 ;;
    esac
    if [ "$_p" = "$_r" ]; then
        return 0
    fi
    return 1
}

has_dist_newstyle() {
    _p=$(canonical "$1")
    case "$_p" in
        */dist-newstyle/*|*/dist-newstyle) return 0 ;;
    esac
    return 1
}

check_inherited_env() {
    if [ "${LD_LIBRARY_PATH+set}" = set ]; then
        refuse 'inherited LD_LIBRARY_PATH'
        return 2
    fi
    if [ "${LD_PRELOAD+set}" = set ]; then
        refuse 'inherited LD_PRELOAD'
        return 2
    fi
    if [ "${HASKOKI_CONFIG+set}" = set ]; then
        refuse 'inherited HASKOKI_CONFIG'
        return 2
    fi
}

check_module_path() {
    _mod=$1
    _co=$2
    case "$_mod" in
        /*) : ;;
        *) refuse 'module path not absolute'; return 2 ;;
    esac
    if is_inside "$_mod" "$_co"; then
        refuse 'module inside the source checkout'
        return 2
    fi
    if has_dist_newstyle "$_mod"; then
        refuse 'source-tree build path'
        return 2
    fi
    if [ ! -f "$_mod" ]; then
        refuse 'module file missing'
        return 2
    fi
    _real=$(canonical "$_mod")
    _lib=$(dirname -- "$_real")
    _prefix=$(dirname -- "$_lib")
    if [ ! -f "$_prefix/toolchain-record.txt" ]; then
        refuse 'not an installed bundle'
        return 2
    fi
    if [ ! -f "$_prefix/closure/review.txt" ]; then
        refuse 'not an installed bundle'
        return 2
    fi
    if [ ! -x "$_prefix/bin/haskoki-ctl" ]; then
        refuse 'not an installed bundle'
        return 2
    fi
}

check_bundle_tar() {
    case "$1" in
        /*) : ;;
        *) refuse 'bundle path not absolute'; return 2 ;;
    esac
    if [ ! -f "$1" ]; then
        refuse 'bundle file missing'
        return 2
    fi
}

check_native_dir() {
    case "$1" in
        /*) : ;;
        *) refuse 'native dir not absolute'; return 2 ;;
    esac
    if [ ! -f "$1/token_fixture" ] || [ ! -x "$1/token_fixture" ]; then
        refuse 'native binary missing'
        return 2
    fi
}

check_out() {
    case "$1" in
        /*) : ;;
        *) refuse 'output root not absolute'; return 2 ;;
    esac
    if is_inside "$1" "$2"; then
        refuse 'output root inside the checkout'
        return 2
    fi
    if [ -e "$1" ] || [ -L "$1" ]; then
        refuse 'output root exists'
        return 2
    fi
}

check_out_existing() {
    case "$1" in
        /*) : ;;
        *) refuse 'run directory not absolute'; return 2 ;;
    esac
    if [ ! -d "$1" ]; then
        refuse 'run directory missing'
        return 2
    fi
    if ! python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if "module" in (s.get("phases_complete") or []) else 1)' "$1/summary.json" >/dev/null 2>&1; then
        refuse 'module phase incomplete'
        return 2
    fi
}

check_module_source() {
    if [ -n "$1" ] && [ -n "$2" ]; then
        refuse 'choose one module source'
        return 2
    fi
    if [ -z "$1" ] && [ -z "$2" ]; then
        refuse 'module source missing'
        return 2
    fi
}

check_profile() {
    case "$1" in
        portfolio|image) : ;;
        *) refuse 'unknown profile'; return 2 ;;
    esac
}

measure_source() {
    _co=$1
    _fsha=$2
    _fdirty=$3
    _have_git=0
    if command -v git >/dev/null 2>&1; then
        if git -C "$_co" rev-parse --show-toplevel >/dev/null 2>&1; then
            _have_git=1
        fi
    fi
    if [ "$_have_git" -eq 1 ]; then
        if ! SOURCE_SHA=$(git -C "$_co" rev-parse HEAD 2>/dev/null); then
            refuse 'source sha unavailable'
            return 2
        fi
        if _porc=$(git -C "$_co" status --porcelain 2>/dev/null); then
            if [ -n "$_porc" ]; then
                SOURCE_DIRTY=true
            else
                SOURCE_DIRTY=false
            fi
            SOURCE_DIRTY_BASIS=measured
        else
            refuse 'source dirty unavailable'
            return 2
        fi
    else
        if [ -z "$_fsha" ]; then
            refuse 'source sha unavailable'
            return 2
        fi
        SOURCE_SHA=$_fsha
        if [ -z "$_fdirty" ]; then
            refuse 'source dirty flag required'
            return 2
        fi
        case "$_fdirty" in
            true|false) SOURCE_DIRTY=$_fdirty ;;
            *) refuse 'source dirty flag malformed'; return 2 ;;
        esac
        SOURCE_DIRTY_BASIS=caller
    fi
}

print_usage() {
    printf '%s\n' "usage: test-client-journeys.sh --profile portfolio|image --out ABS_NEW_DIR (--bundle-tar ABS_FILE | --module ABS_FILE) --native-dir ABS_DIR [--phase all|module] [--artifact-image ID] [--source-sha SHA --source-dirty true|false] [--client-setup-seconds N] [--legs FILE]" >&2
    printf '%s\n' "       test-client-journeys.sh --profile P --phase verifier --out-existing ABS_RUN_DIR [--legs FILE]" >&2
    printf '%s\n' "       test-client-journeys.sh --check ABS_RUN_DIR --profile P [--legs FILE]" >&2
    printf '%s\n' "       test-client-journeys.sh --build-native ABS_NEW_DIR" >&2
    printf '%s\n' "       test-client-journeys.sh --self-test" >&2
}

run_selftest() {
    unset LD_LIBRARY_PATH LD_PRELOAD HASKOKI_CONFIG
    _tmp=$(mktemp -d "${TMPDIR:-/tmp}/journeys-driver-check.XXXXXX")
    trap 'rm -rf "$_tmp"' EXIT INT TERM
    _pass=0
    _total=16
    _fake="$_tmp/fake"
    mkdir -p "$_fake/lib" "$_fake/closure" "$_fake/bin"
    : > "$_fake/lib/libhaskoki.so"
    printf 'fake-toolchain\n' > "$_fake/toolchain-record.txt"
    printf 'fake-review\n' > "$_fake/closure/review.txt"
    printf '#!/bin/sh\nexit 0\n' > "$_fake/bin/haskoki-ctl"
    chmod +x "$_fake/bin/haskoki-ctl"
    _native="$_tmp/native"
    mkdir -p "$_native"
    printf '#!/bin/sh\nexit 0\n' > "$_native/token_fixture"
    chmod +x "$_native/token_fixture"
    if ! _co=$(find_checkout 2>"$_tmp/checkout-err"); then
        printf 'FAIL: cannot locate the checkout\n'
        printf 'SELF-TEST: FAIL %s/%s\n' "$_pass" "$_total"
        return 1
    fi
    if check_module_path 'lib/libhaskoki.so' "$_co" 2>"$_tmp/c1"; then
        printf 'FAIL: control 1 accepted a relative module path\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 1 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'module path not absolute' "$_tmp/c1" 2>/dev/null; then
            printf 'FAIL: control 1 reason mismatch\n'
        else
            printf 'ok: control 1 relative module path refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if check_module_path "$_co/dist-newstyle/x/libhaskoki.so" "$_co" 2>"$_tmp/c2"; then
        printf 'FAIL: control 2 accepted a module inside the checkout\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 2 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'module inside the source checkout' "$_tmp/c2" 2>/dev/null; then
            printf 'FAIL: control 2 reason mismatch\n'
        else
            printf 'ok: control 2 module inside the checkout refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if check_module_path "$_tmp/outside/dist-newstyle/x/libhaskoki.so" "$_co" 2>"$_tmp/c3"; then
        printf 'FAIL: control 3 accepted a source-tree build path\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 3 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'source-tree build path' "$_tmp/c3" 2>/dev/null; then
            printf 'FAIL: control 3 reason mismatch\n'
        else
            printf 'ok: control 3 source-tree build path refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    mkdir -p "$_tmp/nomarkers/lib"
    : > "$_tmp/nomarkers/lib/libhaskoki.so"
    if check_module_path "$_tmp/nomarkers/lib/libhaskoki.so" "$_co" 2>"$_tmp/c4"; then
        printf 'FAIL: control 4 accepted a module without bundle markers\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 4 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'not an installed bundle' "$_tmp/c4" 2>/dev/null; then
            printf 'FAIL: control 4 reason mismatch\n'
        else
            printf 'ok: control 4 module without bundle markers refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if (LD_LIBRARY_PATH=/x; export LD_LIBRARY_PATH; check_inherited_env) 2>"$_tmp/c5"; then
        printf 'FAIL: control 5 accepted an inherited library path\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 5 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'inherited LD_LIBRARY_PATH' "$_tmp/c5" 2>/dev/null; then
            printf 'FAIL: control 5 reason mismatch\n'
        else
            printf 'ok: control 5 inherited library path refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if (HASKOKI_CONFIG=/x; export HASKOKI_CONFIG; check_inherited_env) 2>"$_tmp/c6"; then
        printf 'FAIL: control 6 accepted an inherited store config\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 6 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'inherited HASKOKI_CONFIG' "$_tmp/c6" 2>/dev/null; then
            printf 'FAIL: control 6 reason mismatch\n'
        else
            printf 'ok: control 6 inherited store config refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if check_out "$_tmp" "$_co" 2>"$_tmp/c7"; then
        printf 'FAIL: control 7 accepted an existing output root\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 7 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'output root exists' "$_tmp/c7" 2>/dev/null; then
            printf 'FAIL: control 7 reason mismatch\n'
        else
            printf 'ok: control 7 existing output root refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if check_out "$_co/tmp-journeys-driver-check-$$" "$_co" 2>"$_tmp/c8"; then
        printf 'FAIL: control 8 accepted an output root inside the checkout\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 8 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'output root inside the checkout' "$_tmp/c8" 2>/dev/null; then
            printf 'FAIL: control 8 reason mismatch\n'
        else
            printf 'ok: control 8 output root inside the checkout refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if check_module_source "$_fake/lib/libhaskoki.so" "$_tmp/bundle.tar.gz" 2>"$_tmp/c9"; then
        printf 'FAIL: control 9 accepted two module sources\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 9 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'choose one module source' "$_tmp/c9" 2>/dev/null; then
            printf 'FAIL: control 9 reason mismatch\n'
        else
            printf 'ok: control 9 two module sources refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    mkdir -p "$_tmp/empty-native"
    if check_native_dir "$_tmp/empty-native" 2>"$_tmp/c10"; then
        printf 'FAIL: control 10 accepted a native dir without the fixture\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 10 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'native binary missing' "$_tmp/c10" 2>/dev/null; then
            printf 'FAIL: control 10 reason mismatch\n'
        else
            printf 'ok: control 10 native dir without the fixture refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    _syn="$_tmp/synthetic-legs.json"
    cat > "$_syn" <<'SYN_EOF'
{
  "$schema": "haskoki-journey-legs/1",
  "clients": {
    "runner": {
      "package": null,
      "package_version": null,
      "runtime_argv": null,
      "runtime_version": null
    }
  },
  "profiles": {
    "portfolio": {
      "description": "Driver control fixture: one setup leg with an absent binary.",
      "clients": ["runner"],
      "phases": ["module"]
    }
  },
  "legs": [
    {
      "name": "synthetic-setup-probe",
      "profiles": ["portfolio"],
      "phase": "module",
      "client": "runner",
      "store": "synthetic-store",
      "argv": ["/nonexistent-journey-binary-xyz"],
      "env": {},
      "timeout_seconds": 10,
      "expect": {"exit": 0, "markers": ["synthetic marker never printed"]},
      "depends_on": []
    }
  ]
}
SYN_EOF
    _run_out="$_tmp/final-run"
    _src=$(find_src_root 2>"$_tmp/c11-src") || {
        printf 'FAIL: control 11 cannot locate the source root\n'
        printf 'SELF-TEST: FAIL %s/%s\n' "$_pass" "$_total"
        return 1
    }
    if ! check_module_path "$_fake/lib/libhaskoki.so" "$_co" 2>"$_tmp/c11-g1"; then
        printf 'FAIL: control 11 fake tree trips the module guard\n'
    elif ! check_native_dir "$_native" 2>"$_tmp/c11-g2"; then
        printf 'FAIL: control 11 fake tree trips the native guard\n'
    elif ! check_out "$_run_out" "$_co" 2>"$_tmp/c11-g3"; then
        printf 'FAIL: control 11 fake tree trips the output guard\n'
    elif ! check_inherited_env 2>"$_tmp/c11-g4"; then
        printf 'FAIL: control 11 fake tree trips the environment guard\n'
    elif python3 -I "$_src/tests/journeys/journeys.py" run --profile portfolio --out "$_run_out" --module "$_fake/lib/libhaskoki.so" --native-dir "$_native" --legs "$_syn" --source-sha 0000000000000000000000000000000000000000 --source-dirty false --source-dirty-basis caller >"$_tmp/c11.log" 2>&1; then
        printf 'FAIL: control 11 aggregate passed on an empty module\n'
    else
        _rc=$?
        if [ "$_rc" -ne 1 ]; then
            printf 'FAIL: control 11 exit %s, want 1\n' "$_rc"
        elif ! grep -q 'JR-SETUP' "$_tmp/c11.log" 2>/dev/null; then
            printf 'FAIL: control 11 aggregate lacks a setup finding\n'
        else
            printf 'ok: control 11 empty module fails the aggregate\n'
            _pass=$((_pass + 1))
        fi
    fi
    if (LD_LIBRARY_PATH=; export LD_LIBRARY_PATH; check_inherited_env) 2>"$_tmp/c12"; then
        printf 'FAIL: control 12 accepted an empty inherited library path\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 12 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'inherited LD_LIBRARY_PATH' "$_tmp/c12" 2>/dev/null; then
            printf 'FAIL: control 12 reason mismatch\n'
        else
            printf 'ok: control 12 empty inherited library path refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if (LD_PRELOAD=; export LD_PRELOAD; check_inherited_env) 2>"$_tmp/c13"; then
        printf 'FAIL: control 13 accepted an empty inherited preload\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 13 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'inherited LD_PRELOAD' "$_tmp/c13" 2>/dev/null; then
            printf 'FAIL: control 13 reason mismatch\n'
        else
            printf 'ok: control 13 empty inherited preload refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if (HASKOKI_CONFIG=; export HASKOKI_CONFIG; check_inherited_env) 2>"$_tmp/c14"; then
        printf 'FAIL: control 14 accepted an empty inherited store config\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 14 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'inherited HASKOKI_CONFIG' "$_tmp/c14" 2>/dev/null; then
            printf 'FAIL: control 14 reason mismatch\n'
        else
            printf 'ok: control 14 empty inherited store config refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    ln -s "$_tmp/no-such-target-$$" "$_tmp/dangling-out"
    if check_out "$_tmp/dangling-out" "$_co" 2>"$_tmp/c15"; then
        printf 'FAIL: control 15 accepted a dangling output symlink\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 15 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'output root exists' "$_tmp/c15" 2>/dev/null; then
            printf 'FAIL: control 15 reason mismatch\n'
        else
            printf 'ok: control 15 dangling output symlink refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    mkdir -p "$_tmp/dir-native/token_fixture"
    if check_native_dir "$_tmp/dir-native" 2>"$_tmp/c16"; then
        printf 'FAIL: control 16 accepted a native fixture that is a directory\n'
    else
        _rc=$?
        if [ "$_rc" -ne 2 ]; then
            printf 'FAIL: control 16 exit %s, want 2\n' "$_rc"
        elif ! grep -q 'native binary missing' "$_tmp/c16" 2>/dev/null; then
            printf 'FAIL: control 16 reason mismatch\n'
        else
            printf 'ok: control 16 native fixture that is a directory refused\n'
            _pass=$((_pass + 1))
        fi
    fi
    if [ "$_pass" -eq "$_total" ]; then
        printf 'SELF-TEST: PASS %s/%s\n' "$_pass" "$_total"
        return 0
    fi
    printf 'SELF-TEST: FAIL %s/%s\n' "$_pass" "$_total"
    return 1
}

PROFILE=
OUT=
OUT_EXISTING=
MODULE=
BUNDLE_TAR=
NATIVE_DIR=
PHASE=
ARTIFACT_IMAGE=
SOURCE_SHA_FLAG=
SOURCE_DIRTY_FLAG=
CLIENT_SETUP_SECONDS=
LEGS_FLAG=
CHECK_DIR=
BUILD_NATIVE=
SELFTEST=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile) PROFILE=${2-}; shift 2 ;;
        --profile=*) PROFILE=${1#--profile=}; shift ;;
        --out) OUT=${2-}; shift 2 ;;
        --out=*) OUT=${1#--out=}; shift ;;
        --out-existing) OUT_EXISTING=${2-}; shift 2 ;;
        --out-existing=*) OUT_EXISTING=${1#--out-existing=}; shift ;;
        --module) MODULE=${2-}; shift 2 ;;
        --module=*) MODULE=${1#--module=}; shift ;;
        --bundle-tar) BUNDLE_TAR=${2-}; shift 2 ;;
        --bundle-tar=*) BUNDLE_TAR=${1#--bundle-tar=}; shift ;;
        --native-dir) NATIVE_DIR=${2-}; shift 2 ;;
        --native-dir=*) NATIVE_DIR=${1#--native-dir=}; shift ;;
        --phase) PHASE=${2-}; shift 2 ;;
        --phase=*) PHASE=${1#--phase=}; shift ;;
        --artifact-image) ARTIFACT_IMAGE=${2-}; shift 2 ;;
        --artifact-image=*) ARTIFACT_IMAGE=${1#--artifact-image=}; shift ;;
        --source-sha) SOURCE_SHA_FLAG=${2-}; shift 2 ;;
        --source-sha=*) SOURCE_SHA_FLAG=${1#--source-sha=}; shift ;;
        --source-dirty) SOURCE_DIRTY_FLAG=${2-}; shift 2 ;;
        --source-dirty=*) SOURCE_DIRTY_FLAG=${1#--source-dirty=}; shift ;;
        --client-setup-seconds) CLIENT_SETUP_SECONDS=${2-}; shift 2 ;;
        --client-setup-seconds=*) CLIENT_SETUP_SECONDS=${1#--client-setup-seconds=}; shift ;;
        --legs) LEGS_FLAG=${2-}; shift 2 ;;
        --legs=*) LEGS_FLAG=${1#--legs=}; shift ;;
        --check) CHECK_DIR=${2-}; shift 2 ;;
        --check=*) CHECK_DIR=${1#--check=}; shift ;;
        --build-native) BUILD_NATIVE=${2-}; shift 2 ;;
        --build-native=*) BUILD_NATIVE=${1#--build-native=}; shift ;;
        --self-test) SELFTEST=1; shift ;;
        --help|-h) print_usage; exit 0 ;;
        --) shift; break ;;
        -*) printf 'unknown option: %s\n' "$1" >&2; print_usage; exit 2 ;;
        *) printf 'unexpected argument: %s\n' "$1" >&2; print_usage; exit 2 ;;
    esac
done

if [ "$SELFTEST" -eq 1 ]; then
    run_selftest
    exit "$?"
fi

if [ -n "$BUILD_NATIVE" ]; then
    refuse 'build-native unavailable'
    exit 2
fi

SRC_ROOT=$(find_src_root) || exit 2
if [ -z "$LEGS_FLAG" ]; then
    LEGS_PATH="$SRC_ROOT/tests/journeys/legs.json"
else
    LEGS_PATH=$LEGS_FLAG
fi
ENGINE="$SRC_ROOT/tests/journeys/journeys.py"

if [ -n "$CHECK_DIR" ]; then
    if [ -z "$PROFILE" ]; then
        refuse 'profile required'
        exit 2
    fi
    check_profile "$PROFILE" || exit 2
    exec python3 -I "$ENGINE" check "$CHECK_DIR" --profile "$PROFILE" --legs "$LEGS_PATH"
fi

if [ -n "$OUT_EXISTING" ]; then
    if [ -n "$OUT" ]; then
        refuse 'choose one output root'
        exit 2
    fi
    if [ -z "$PROFILE" ]; then
        refuse 'profile required'
        exit 2
    fi
    if [ -z "$PHASE" ]; then
        PHASE=verifier
    fi
    if [ "$PHASE" != "verifier" ]; then
        refuse 'existing run takes the verifier phase only'
        exit 2
    fi
    if [ -n "$MODULE" ] || [ -n "$BUNDLE_TAR" ]; then
        refuse 'existing run reuses its module'
        exit 2
    fi
    check_profile "$PROFILE" || exit 2
    check_inherited_env || exit 2
    check_out_existing "$OUT_EXISTING" || exit 2
    exec python3 -I "$ENGINE" run --profile "$PROFILE" --phase verifier --out-existing "$OUT_EXISTING" --legs "$LEGS_PATH"
fi

if [ -n "$OUT" ]; then
    if [ -z "$PROFILE" ]; then
        refuse 'profile required'
        exit 2
    fi
    if [ -z "$PHASE" ]; then
        PHASE=all
    fi
    case "$PHASE" in
        all|module) : ;;
        verifier) refuse 'verifier phase needs an existing run'; exit 2 ;;
        *) refuse 'unknown phase'; exit 2 ;;
    esac
    if [ -z "$NATIVE_DIR" ]; then
        refuse 'native dir missing'
        exit 2
    fi
    CHECKOUT=$(find_checkout) || exit 2
    check_profile "$PROFILE" || exit 2
    check_inherited_env || exit 2
    check_module_source "$MODULE" "$BUNDLE_TAR" || exit 2
    if [ -n "$MODULE" ]; then
        check_module_path "$MODULE" "$CHECKOUT" || exit 2
    else
        check_bundle_tar "$BUNDLE_TAR" || exit 2
    fi
    check_native_dir "$NATIVE_DIR" || exit 2
    check_out "$OUT" "$CHECKOUT" || exit 2
    case "$LEGS_PATH" in
        /*) : ;;
        *) refuse 'legs path not absolute'; exit 2 ;;
    esac
    if [ ! -f "$LEGS_PATH" ]; then
        refuse 'legs file missing'
        exit 2
    fi
    measure_source "$CHECKOUT" "$SOURCE_SHA_FLAG" "$SOURCE_DIRTY_FLAG" || exit 2
    if [ -n "$MODULE" ]; then
        set -- python3 -I "$ENGINE" run --profile "$PROFILE" --out "$OUT" --module "$MODULE" --native-dir "$NATIVE_DIR" --phase "$PHASE" --legs "$LEGS_PATH" --source-sha "$SOURCE_SHA" --source-dirty "$SOURCE_DIRTY" --source-dirty-basis "$SOURCE_DIRTY_BASIS"
    else
        set -- python3 -I "$ENGINE" run --profile "$PROFILE" --out "$OUT" --bundle-tar "$BUNDLE_TAR" --native-dir "$NATIVE_DIR" --phase "$PHASE" --legs "$LEGS_PATH" --source-sha "$SOURCE_SHA" --source-dirty "$SOURCE_DIRTY" --source-dirty-basis "$SOURCE_DIRTY_BASIS"
    fi
    if [ -n "$ARTIFACT_IMAGE" ]; then
        set -- "$@" --artifact-image "$ARTIFACT_IMAGE"
    fi
    if [ -n "$CLIENT_SETUP_SECONDS" ]; then
        set -- "$@" --client-setup-seconds "$CLIENT_SETUP_SECONDS"
    fi
    exec "$@"
fi

print_usage
exit 2
