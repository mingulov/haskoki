#!/bin/sh
# scripts/test-proxy-parity.sh -- direct-vs-proxied parity driver.
#
# Runs the SAME native C consumer scenarios (tests/c/consumer_*.c) both
# directly against the built shared module and behind pkcs11-proxy-ng,
# and demands byte-identical transcripts over the topology-independent
# (forwarded-call) lines: parity = same CKR + same outputs direct vs
# proxied. Topology-specific lines ("topology:", "invent:", "crypto:",
# "routed:" prefixes) are asserted strictly per mode by the scenarios
# themselves but excluded from the diff — see
# the 2026-09-21 proxy-parity session notes for each exclusion's cited
# mechanism (shim fixed catalog, NULL-on-miss contract, shim-side
# session validation, absent vendor trampolines).
#
# Proxy provenance (external binaries, never built into the repo):
#   source: https://github.com/mingulov/pkcs11-proxy-ng
#   commit: a48b60ba54b0163f4999c1e4fc0514bf7dc01681
#   built:  throwaway rust:1.94-bookworm container,
#             apt-get install protobuf-compiler && cargo build --release
#           artifacts: pkcs11-proxy-ng (daemon) +
#             libpkcs11_proxy_ng_shim.so (loadable shim)
#   env:    HASKOKI_PROXY_DIR (default /opt/pkcs11-proxy-ng) must hold
#           both artifacts; HASKOKI_PROXY_PORT (default 17512) selects
#           the loopback listener.
#
# Canonical build (the ONLY authoritative hashes):
#   daemon sha256:
#     260cb245981561291eab4d29a16cb6a4d6f00dca3431f3d583d35364fab0c9e5  pkcs11-proxy-ng
#   shim sha256:
#     8ea85073ce8436ebdc8ee99bce99e70a6d8c34473c28b5a45567c8a26aba1690  libpkcs11_proxy_ng_shim.so
#   repro: from a pristine checkout of the source above at the commit
#   above (no target/ dir), run the pinned-toolchain recipe:
#     timeout -s KILL 2400 docker run --rm --network host \
#       -v <src>:/src -w /src rust:1.94-bookworm \
#       bash -c 'apt-get update -qq && apt-get install -y -qq \
#         protobuf-compiler && cargo build --release'
#     sha256sum target/release/pkcs11-proxy-ng \
#       target/release/libpkcs11_proxy_ng_shim.so
#   The two hashes MUST match the pair above (verified 2026-09-23:
#   a fresh build from pristine source reproduced them
#   byte-identically; build log kept by the reviewer).
#
# Historical /tmp builds (a past review concern): EIGHT
# divergent pairs were found under /tmp (five hash-distinct).
# None carried recorded provenance, so none was authoritative;
# all were deleted during review. Any /tmp pair found later
# MUST be rebuilt from the pinned commit + recipe and re-pinned
# here before use; unrecorded binaries are never authoritative.
#
# Residual tree (recorded during review): /tmp/pkcs11-proxy-ng/target/release/
# holds a build at the pinned a48b60b commit (clean checkout) whose
# artifacts are byte-identical to the canonical pair above (verified
# by the reviewer with their own sha256; re-verified separately).
#
# Sensitivity proof (a parity script that cannot fail is theater):
#   HASKOKI_PARITY_SEED_MISMATCH=1 corrupts one side's transcript
#   before the diff; the script MUST fail and report the divergent
#   call plus both outputs.
#
# Usage:
#   scripts/test-proxy-parity.sh             # full parity (must PASS)
#   HASKOKI_PARITY_SEED_MISMATCH=1 scripts/test-proxy-parity.sh
#                                           # must FAIL (seeded)
#
# Run (from haskoki/), inside the Docker toolchain image via bind mount:
#   docker run --rm -v "$PWD:/work" -w /work \
#     -v <proxy-dir>:/opt/pkcs11-proxy-ng:ro \
#     haskoki-dev:ghc-9.10.3 scripts/test-proxy-parity.sh
#
# Exit status: 0 iff every scenario passes in BOTH topologies and all
# forwarded-call transcripts are identical.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

PROXY_COMMIT="a48b60ba54b0163f4999c1e4fc0514bf7dc01681"
PROXY_DIR="${HASKOKI_PROXY_DIR:-/opt/pkcs11-proxy-ng}"
PROXY_PORT="${HASKOKI_PROXY_PORT:-17512}"
ENDPOINT="http://127.0.0.1:$PROXY_PORT"
SERVER_BIN="$PROXY_DIR/pkcs11-proxy-ng"
SHIM_SO="$PROXY_DIR/libpkcs11_proxy_ng_shim.so"

fail() {
  echo "FAIL: $1"
  exit 1
}

[ -x "$SERVER_BIN" ] || fail "proxy daemon missing/not executable: $SERVER_BIN (build per header recipe into HASKOKI_PROXY_DIR)"
[ -f "$SHIM_SO" ] || fail "proxy shim missing: $SHIM_SO (build per header recipe into HASKOKI_PROXY_DIR)"
echo "proxy commit (recorded): $PROXY_COMMIT"
"$SERVER_BIN" --version 2>&1 | head -1 || fail "proxy daemon --version failed"
for sym in C_GetFunctionList C_GetInterfaceList C_GetInterface; do
  if ! nm -D --defined-only "$SHIM_SO" 2>/dev/null | grep -q " T $sym$"; then
    fail "shim export missing from $SHIM_SO: $sym"
  fi
done
echo "STATIC: shim exports discovery surface"

cabal build all || fail "cabal build all failed"

# Locate exactly one built shared module (absolute path: the daemon
# config carries it and the daemon dlopens it).
SO_LIST=$(find "$PWD/dist-newstyle" -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
if [ -z "$SO_LIST" ]; then
  fail "no loadable module found (run: cabal build all)"
fi
if [ "$SO_COUNT" -ne 1 ]; then
  echo "found candidates:"
  echo "$SO_LIST"
  fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
fi
SO="$SO_LIST"
echo "module under test: $SO"

SCEN_LIST=$(ls tests/c/consumer_*.c 2>/dev/null | sort)
if [ -z "$SCEN_LIST" ]; then
  fail "no consumer scenarios found (expected tests/c/consumer_*.c)"
fi

TMPD="${TMPDIR:-/tmp}/haskoki-parity"
mkdir -p "$TMPD" || fail "cannot create $TMPD"

# Backend config for the daemon side (real-crypto engine, trace off).
cat > "$TMPD/backend.toml" <<'EOF'
schema_version = 1
profile = "real-crypto"
[storage]
kind = "memory"
[engine]
kind = "openssl"
allow_synthetic_fallback = false
private_library_context = true
[trace]
enabled = false
EOF

# Daemon config (loopback dev shape; see proxy examples/).
cat > "$TMPD/proxy.toml" <<EOF
[backend]
module = "$SO"

[proxy]
mechanism_discovery = "transparent"
lease_seconds = 600
request_timeout_secs = 60
max_concurrent_backend_calls = 200
max_blocking_threads = 512

[listener.remote]
bind = "127.0.0.1:$PROXY_PORT"
auth = "none"
allow_insecure_tcp = true
EOF

# Shim mechanism override (PKCS11_PROXY_MECHANISMS): the pinned
# proxy's embedded shape table maps CK_SIGN_ADDITIONAL_CONTEXT
# only to CKM_ML_DSA (0x001D); CKM_SLH_DSA (0x002E) takes the
# identical struct but has no entry, so struct-param SLH legs
# fail proxied while NULL-param legs pass. The override merges
# per-mechanism over the embedded defaults (proxy
# MechanismRegistry::merge_config: additive insert, existing
# entries untouched), so these mappings are the whole delta —
# no proxy rebuild, no re-pin. Upstream should gain 0x002E in
# mechanism_params_default.toml next to 0x001D, and 0x401D next
# to the other *_HMAC_GENERAL rows; until then this file is the
# recorded extension point (extend here, never fork
# the pinned binaries).
cat > "$TMPD/mechanisms-override.toml" <<'EOF'
[[params]]
shape = "sign_additional_context"
mechanisms = [
    0x002E,  # CKM_SLH_DSA (optional -- hedge mode, same struct as ML-DSA)
]

[[params]]
shape = "mac_general"
mechanisms = [
    0x401D,  # CKM_BLAKE2B_512_HMAC_GENERAL (CK_ULONG tag length, same shape as SHA*_HMAC_GENERAL)
    0x1084,  # CKM_AES_MAC_GENERAL (11f)
    0x0564,  # CKM_ARIA_MAC_GENERAL (11f)
    0x0554,  # CKM_CAMELLIA_MAC_GENERAL (11f)
]

[[params]]
shape = "gcm"
mechanisms = [
    0x108E,  # CKM_AES_GMAC (CK_GCM_PARAMS, same struct as AES-GCM) (11f)
]

[[params]]
shape = "ssl3_master_key_derive"
mechanisms = [
    0x0375,  # CKM_TLS_MASTER_KEY_DERIVE (CK_SSL3_MASTER_KEY_DERIVE_PARAMS, same struct as the SSL3 rows) (11i)
    0x0377,  # CKM_TLS_MASTER_KEY_DERIVE_DH (same struct) (11i)
]
EOF

compile_scenario() {
  base=$(basename "$1" .c)
  cc -std=c11 -O2 -g -Wall -Wextra -Werror \
    -Ispec/vendor \
    -o "$TMPD/$base" "$1" -ldl -lpthread \
    || fail "$base did not compile"
  echo "scenario compiled: $TMPD/$base"
}

for scen in $SCEN_LIST; do
  compile_scenario "$scen"
done

# Start the daemon (backend = our module under its own config).
RUST_LOG=info HASKOKI_CONFIG="$TMPD/backend.toml" "$SERVER_BIN" "$TMPD/proxy.toml" \
  >"$TMPD/server.log" 2>&1 &
SRV=$!
cleanup() {
  kill $SRV 2>/dev/null || true
}
trap cleanup EXIT

# Readiness: TCP accept on the port. The daemon binds only after the
# backend loads and its slot map populates (main.rs: load_backend ->
# populate_slots -> serve), so an accepting socket plus a live process
# means fully ready. (Plain-HTTP probes do not work: the listener is
# gRPC/h2c-prior-knowledge and never answers HTTP/1.1.)
command -v bash >/dev/null 2>&1 || fail "bash required for TCP readiness probe"
READY=0
i=0
while [ "$i" -lt 30 ]; do
  if ! kill -0 $SRV 2>/dev/null; then
    echo "--- daemon log:"; cat "$TMPD/server.log"
    fail "proxy daemon died during startup"
  fi
  if bash -c "echo > /dev/tcp/127.0.0.1/$PROXY_PORT" 2>/dev/null; then
    READY=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "--- daemon log:"; cat "$TMPD/server.log"
  fail "proxy daemon not listening on $ENDPOINT after 30s"
fi
echo "proxy daemon ready: $ENDPOINT (pid $SRV)"

normalize() {
  # $1 = raw log, $2 = normalized output: drop topology-specific
  # lines, reduce the PASS path to the bare scenario name.
  grep -v -e '^topology:' -e '^invent:' -e '^crypto:' -e '^routed:' "$1" \
    | sed -e 's|^PASS: \([A-Za-z0-9_]*\) (.*)$|PASS: \1|' > "$2"
}

run_parity() {
  # $1 = scenario base name
  base="$1"
  BIN="$TMPD/$base"
  DLOG="$TMPD/$base.direct.log"
  PLOG="$TMPD/$base.proxied.log"
  DNORM="$TMPD/$base.direct.norm"
  PNORM="$TMPD/$base.proxied.norm"
  echo "--- parity: $base"
  env -u HASKOKI_CONSUMER_TOPOLOGY "$BIN" "$SO" >"$DLOG" 2>&1 \
    || { echo "--- direct log:"; cat "$DLOG"; fail "$base FAILED direct"; }
  echo "direct exit 0"
  HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    PKCS11_PROXY_MECHANISMS="$TMPD/mechanisms-override.toml" \
    "$BIN" "$SHIM_SO" >"$PLOG" 2>&1 \
    || { echo "--- proxied log:"; cat "$PLOG"; fail "$base FAILED proxied"; }
  echo "proxied exit 0"
  normalize "$DLOG" "$DNORM"
  normalize "$PLOG" "$PNORM"
  if [ "${HASKOKI_PARITY_SEED_MISMATCH:-0}" = "1" ]; then
    echo "ok: SEED-INJECTED-DIVERGENCE (sensitivity proof)" >> "$PNORM"
    echo "SEEDED: injected one divergent line into proxied transcript"
  fi
  if ! diff -u "$DNORM" "$PNORM" > "$TMPD/$base.diff"; then
    echo "PARITY DIVERGENCE in $base (first divergent call + outputs):"
    cat "$TMPD/$base.diff"
    echo "--- full direct log:"
    cat "$DLOG"
    echo "--- full proxied log:"
    cat "$PLOG"
    fail "$base: forwarded-call transcripts differ direct-vs-proxied"
  fi
  echo "parity holds: $base ($(wc -l < "$DNORM") forwarded lines identical)"
}

if [ -n "${1:-}" ]; then
  fail "usage: scripts/test-proxy-parity.sh"
fi

for scen in $SCEN_LIST; do
  run_parity "$(basename "$scen" .c)"
done

echo "PASS: test-proxy-parity.sh (direct/proxy parity)"
