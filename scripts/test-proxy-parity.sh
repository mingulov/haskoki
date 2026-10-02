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

[ -f tests/c/message_routed.c ] || fail "message consumer missing"
[ -f tests/c/async_routed.c ] || fail "async consumer missing"
[ -f tests/c/notifications_routed.c ] || fail "notifications consumer missing"
[ -f tests/c/consumer_certificates.c ] || fail "certificates consumer missing"
[ -f tests/c/consumer_notifications_poll.c ] || fail "notifications polling consumer missing"
SCEN_LIST=$(
  for scen in tests/c/consumer_*.c tests/c/message_routed.c tests/c/async_routed.c tests/c/notifications_routed.c tests/c/consumer_certificates.c; do
    [ -f "$scen" ] && printf '%s\n' "$scen"
  done | LC_ALL=C sort -u
)
[ -n "$SCEN_LIST" ] || fail "consumer scenario list empty"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/message_routed.c')" -eq 1 ] \
  || fail "message consumer must occur exactly once"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/async_routed.c')" -eq 1 ] \
  || fail "async consumer must occur exactly once"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/notifications_routed.c')" -eq 1 ] \
  || fail "notifications consumer must occur exactly once"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/consumer_certificates.c')" -eq 1 ] \
  || fail "certificates consumer must occur exactly once"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/consumer_notifications_poll.c')" -eq 1 ] \
  || fail "notifications polling consumer must occur exactly once"
for scen in $SCEN_LIST; do
  if grep -nE 'abi_generated|abi_stubs|abi-inventory' "$scen"; then
    fail "consumer independence violated: $scen"
  fi
done

# Direct-only scenarios: the pinned proxy cannot transport these calls, so
# the direct leg runs and must pass while the proxied leg and transcript
# diff are skipped with a loud notice. Each entry is base:upstream-issue-URL;
# an entry without a URL, or naming no listed scenario, fails the driver.
# Per-leg entries base:leg:upstream-issue-URL skip only that leg's proxied
# run (whole-basename entries keep working); the leg must be one of the
# six certificate legs.
# Per-version entries consumer_certificates:leg:version:upstream-issue-URL
# skip only that leg+version's proxied run; version is one of
# 2.40/3.0/3.1/3.2 (whole-leg and whole-basename entries keep working).
# message_routed: proxy rejects raw IV params, clobbers output state on
# errors, erases NULL/nonzero shapes, and orders session checks first.
# async_routed: fixed GetID/Join refusals; Complete source cannot preserve
# caller output bindings/capacity. Direct success is not transport parity.
# notifications_routed: blocking Wait retains the shim client mutex needed by
# Finalize; callback association and provider control are not transported.
# Valid empty polling remains parity-eligible in consumer_notifications_poll.
# consumer_certificates:lifecycle+visibility+atomicity: proxied
# C_GetAttributeValue on an invalid handle (destroyed or post-logout
# stale) zeroes the caller canary buffer (direct preserves it); same
# cause, one URL; T-C09 R8.
# consumer_certificates:restart: memory token objects survive client
# Finalize/Initialize through the proxy (direct drops them);
# https://github.com/mingulov/pkcs11-proxy-ng/issues/27; T-C09 R9.
# consumer_certificates:create+find:3.1: v3.1 C_GetInterface returns CKR_OK
# with no usable function table through the proxy (direct yields the 3.1
# table); every 3.1 leg trips the same pre-session discovery gate — same
# cause, one URL;
# https://github.com/mingulov/pkcs11-proxy-ng/issues/28; T-C09 R10.
DIRECT_ONLY="message_routed:https://github.com/mingulov/pkcs11-proxy-ng/issues/23
async_routed:https://github.com/mingulov/pkcs11-proxy-ng/issues/24
notifications_routed:https://github.com/mingulov/pkcs11-proxy-ng/issues/25
consumer_certificates:lifecycle:https://github.com/mingulov/pkcs11-proxy-ng/issues/26
consumer_certificates:visibility:https://github.com/mingulov/pkcs11-proxy-ng/issues/26
consumer_certificates:atomicity:https://github.com/mingulov/pkcs11-proxy-ng/issues/26
consumer_certificates:restart:https://github.com/mingulov/pkcs11-proxy-ng/issues/27
consumer_certificates:create:3.1:https://github.com/mingulov/pkcs11-proxy-ng/issues/28
consumer_certificates:find:3.1:https://github.com/mingulov/pkcs11-proxy-ng/issues/28"
for entry in $DIRECT_ONLY; do
  dname="${entry%%:*}"; durl="${entry#*:}"
  [ -n "$durl" ] && [ "$durl" != "$entry" ] \
    || fail "direct-only entry without issue URL: $entry"
  # Strict disposition grammar (T-C09 R12 C09-02): after the basename
  # strip, the remainder must be exactly a whole-basename URL, a
  # whole-leg leg:URL, or a version-qualified leg:version:URL.
  case "$durl" in
    https://?*)
      ;;
    create:*|find:*|lifecycle:*|visibility:*|atomicity:*|restart:*)
      durl="${durl#*:}"
      case "$durl" in
        https://?*)
          ;;
        2.40:*|3.0:*|3.1:*|3.2:*)
          durl="${durl#*:}"
          case "$durl" in
            https://?*) ;;
            *) fail "malformed direct-only entry" ;;
          esac
          ;;
        *) fail "malformed direct-only entry" ;;
      esac
      ;;
    *) fail "malformed direct-only entry" ;;
  esac
  [ "$(printf '%s\n' "$SCEN_LIST" | grep -cx "tests/c/$dname.c")" -eq 1 ] \
    || fail "direct-only entry not in scenario list: $dname"
done

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
if [ -n "${HASKOKI_PARITY_MODULE:-}" ]; then
  SO="$HASKOKI_PARITY_MODULE"
  [ -f "$SO" ] || fail "HASKOKI_PARITY_MODULE missing: $SO"
  echo "module under test: $SO (HASKOKI_PARITY_MODULE override)"
else
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
fi

TMPD="${TMPDIR:-/tmp}/haskoki-parity"
mkdir -p "$TMPD" || fail "cannot create $TMPD"
ARTIFACTS="${HASKOKI_PARITY_ARTIFACTS:-$TMPD/parity-logs}"
mkdir -p "$ARTIFACTS" || fail "cannot create $ARTIFACTS"
CERT_LEGS="${CERT_LEGS:-create find lifecycle visibility atomicity restart}"
HASKOKI_PARITY_STORAGE="${HASKOKI_PARITY_STORAGE:-memory sqlite}"

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

# Certificate-group backend: the base shape above plus the two-label
# token catalog (equal-length PIN arrays) and kind/path for the mode.
write_cert_backend() {
  # $1 = storage mode, $2 = output path
  if [ "$1" = "sqlite" ]; then
    mkdir -p "$TMPD/cert-$1" || fail "cannot create $TMPD/cert-$1"
  fi
  cat > "$2" <<EOF
schema_version = 1
profile = "real-crypto"
[tokens]
labels = ["haskoki-demo", "certificates-B"]
so_pins = ["5678", "5678"]
user_pins = ["1234", "1234"]
[storage]
kind = "$1"
EOF
  if [ "$1" = "sqlite" ]; then
    echo "path = \"$TMPD/cert-$1/tokens.db\"" >> "$2" \
      || fail "cannot write cert backend path"
  fi
  cat >> "$2" <<'EOF'
[engine]
kind = "openssl"
allow_synthetic_fallback = false
private_library_context = true
[trace]
enabled = false
EOF
}

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
    0x0380,  # CKM_SSL3_MD5_MAC (CK_ULONG bit length, same shape; embedded lists these two rows under NULL params, and the override wins: dropping these two lines fails the proxied MAC legs) (11n)
    0x0381,  # CKM_SSL3_SHA1_MAC (CK_ULONG bit length, same shape; see 0x0380) (11n)
    0x0101,  # CKM_RC2_ECB (bare CK_ULONG effective-bits, same layout; embedded lists it parameterless with no shape so the shim rejects the word-carrying init with PARAM_INVALID, and the override wins: dropping this line fails the proxied leg) (11p)
]

[[params]]
shape = "iv"
mechanisms = [
    0x0153,  # CKM_DES_CFB8 (raw IV, same shape as DES_CBC; embedded lists the other DES rows but not the CFB8/OFB64/CFB64 streams) (11p)
    0x1094,  # CKM_BLOWFISH_CBC_PAD (raw IV, same shape as DES_CBC_PAD; embedded lists no Blowfish rows) (11p)
    0x210C,  # CKM_AES_KEY_WRAP_PKCS7 (raw IV; embedded declares it parameterless with no shape so the shim refuses IV-carrying calls, and the override wins) (post-11s)
    0x403A,  # CKM_PUB_KEY_FROM_PRIV_KEY (paramless row: the byte image forwards raw so the backend's ARGUMENTS_BAD survives; no struct to model, never forwarded on success since success takes NULL params) (11s-4)
]

[[params]]
shape = "ecdh_aes_key_wrap"
mechanisms = [
    0x4038,  # CKM_ECDH_X_AES_KEY_WRAP (CK_ECDH_AES_KEY_WRAP_PARAMS, same struct as the embedded 0x1053 row) (post-11s)
    0x4039,  # CKM_ECDH_COF_AES_KEY_WRAP (CK_ECDH_AES_KEY_WRAP_PARAMS, same struct as the embedded 0x1053 row) (post-11s)
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
    # 0x371/0x373 need no entry: the embedded table already maps the
    # SSL3-native rows to this shape (11n, verified via strings).
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

# Start one daemon per group/mode (backend = our module under the given
# config). Each start keeps the 30s readiness gate; cleanup stops the
# live daemon explicitly (kill + wait, log retained) before the next
# group/mode starts, and still runs on EXIT.
SRV=""
cleanup() {
  if [ -n "${SRV:-}" ]; then
    kill $SRV 2>/dev/null || true
    wait $SRV 2>/dev/null || true
    SRV=""
  fi
}
trap cleanup EXIT
start_daemon() {
  # $1 = backend.toml, $2 = server log
  RUST_LOG=info HASKOKI_CONFIG="$1" "$SERVER_BIN" "$TMPD/proxy.toml" \
    >"$2" 2>&1 &
  SRV=$!
  SERVER_LOG="$2"
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
      echo "--- daemon log:"; cat "$SERVER_LOG"
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
    echo "--- daemon log:"; cat "$SERVER_LOG"
    fail "proxy daemon not listening on $ENDPOINT after 30s"
  fi
  echo "proxy daemon ready: $ENDPOINT (pid $SRV)"
}

normalize() {
  # $1 = raw log, $2 = normalized output: drop topology-specific
  # lines, reduce the PASS path to the bare scenario name.
  grep -v -e '^topology:' -e '^invent:' -e '^crypto:' -e '^routed:' "$1" \
    | sed -e 's|^PASS: \([A-Za-z0-9_]*\) (.*)$|PASS: \1|' > "$2"
}

archive_logs() {
  # $@ = required log paths to preserve under $ARTIFACTS (T-C09 R12
  # C09-05): a missing input or a failed copy fails the driver, so a
  # reported PASS always exports every transcript it claims.
  for f in "$@"; do
    [ -f "$f" ] || fail "archive_logs: required artifact missing: $f"
    cp "$f" "$ARTIFACTS/" || fail "archive_logs: cannot copy $f to $ARTIFACTS"
  done
}

run_parity_cert_leg() {
  # $1 = version, $2 = leg; $CERT_MODE is the LIVE daemon's storage mode
  V="$1"; L="$2"; M="$CERT_MODE"
  D="$TMPD/cert-$M/$V-$L"
  mkdir -p "$D" || fail "cannot create $D"
  chmod 0700 "$D" || fail "cannot chmod $D"
  DLOG="$TMPD/consumer_certificates-$V-$L-$M.direct.log"
  PLOG="$TMPD/consumer_certificates-$V-$L-$M.proxied.log"
  DNORM="$TMPD/consumer_certificates-$V-$L-$M.direct.norm"
  PNORM="$TMPD/consumer_certificates-$V-$L-$M.proxied.norm"
  echo "--- parity leg: consumer_certificates version=$V storage=$M leg=$L"
  echo "child argv: env -u HASKOKI_CONSUMER_TOPOLOGY $BIN $SO --version $V --storage $M --leg $L --directory $D"
  ec=0; env -u HASKOKI_CONSUMER_TOPOLOGY "$BIN" "$SO" --version "$V" --storage "$M" --leg "$L" --directory "$D" >"$DLOG" 2>&1 || ec=$?
  echo "direct exit: consumer_certificates $ec"
  if [ "$ec" -ne 0 ]; then echo "--- direct log:"; cat "$DLOG"; fail "consumer_certificates:$L FAILED direct ($V/$M)"; fi
  for entry in $DIRECT_ONLY; do
    case "$entry" in
      "consumer_certificates:$L:$V:"*)
        echo "DIRECT-ONLY: consumer_certificates:$L:$V (proxied leg skipped, see ${entry#consumer_certificates:$L:$V:})"
        archive_logs "$DLOG"
        return 0
        ;;
      "consumer_certificates:$L:"*)
        case "${entry#consumer_certificates:$L:}" in
          2.40:*|3.0:*|3.1:*|3.2:*)
            # Version-qualified entry for another version: this run proceeds.
            ;;
          https://?*)
            echo "DIRECT-ONLY: consumer_certificates:$L (proxied leg skipped, see ${entry#consumer_certificates:$L:})"
            archive_logs "$DLOG"
            return 0
            ;;
          # Defense in depth (T-C09 R12 C09-02): unreachable
          # post-validation, which rejects malformed entries first.
          *) fail "malformed direct-only entry" ;;
        esac
        ;;
      "consumer_certificates:http"*)
        echo "DIRECT-ONLY: consumer_certificates (proxied leg skipped, see ${entry#consumer_certificates:})"
        archive_logs "$DLOG"
        return 0
        ;;
    esac
  done
  echo "child argv: env HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT=$ENDPOINT PKCS11_PROXY_MECHANISMS=$TMPD/mechanisms-override.toml $BIN $SHIM_SO --version $V --storage $M --leg $L --directory $D"
  ec=0; HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    PKCS11_PROXY_MECHANISMS="$TMPD/mechanisms-override.toml" \
    "$BIN" "$SHIM_SO" --version "$V" --storage "$M" --leg "$L" --directory "$D" >"$PLOG" 2>&1 || ec=$?
  echo "proxied exit: consumer_certificates $ec"
  if [ "$ec" -ne 0 ]; then echo "--- proxied log:"; cat "$PLOG"; fail "consumer_certificates:$L FAILED proxied ($V/$M)"; fi
  normalize "$DLOG" "$DNORM"
  normalize "$PLOG" "$PNORM"
  if [ "${HASKOKI_PARITY_SEED_MISMATCH:-0}" = "1" ]; then
    echo "ok: SEED-INJECTED-DIVERGENCE (sensitivity proof)" >> "$PNORM"
    echo "SEEDED: injected one divergent line into proxied transcript"
  fi
  if ! diff -u "$DNORM" "$PNORM" > "$TMPD/consumer_certificates-$V-$L-$M.diff"; then
    echo "PARITY DIVERGENCE in consumer_certificates:$L ($V/$M):"
    cat "$TMPD/consumer_certificates-$V-$L-$M.diff"
    echo "--- full direct log:"
    cat "$DLOG"
    echo "--- full proxied log:"
    cat "$PLOG"
    fail "consumer_certificates:$L: forwarded-call transcripts differ direct-vs-proxied ($V/$M)"
  fi
  echo "parity holds: consumer_certificates:$L ($V/$M, $(wc -l < "$DNORM") forwarded lines identical)"
  archive_logs "$DLOG" "$PLOG" "$DNORM" "$PNORM" "$TMPD/consumer_certificates-$V-$L-$M.diff"
}

run_parity() {
  # $1 = scenario base name
  base="$1"
  BIN="$TMPD/$base"
  if [ "$base" = "consumer_certificates" ]; then
    echo "--- parity: $base (storage mode $CERT_MODE)"
    for V in 2.40 3.0 3.1 3.2; do
      for L in $CERT_LEGS; do
        run_parity_cert_leg "$V" "$L"
      done
    done
    return 0
  fi
  DLOG="$TMPD/$base.direct.log"
  PLOG="$TMPD/$base.proxied.log"
  DNORM="$TMPD/$base.direct.norm"
  PNORM="$TMPD/$base.proxied.norm"
  echo "--- parity: $base"
  echo "child argv: env -u HASKOKI_CONSUMER_TOPOLOGY $BIN $SO"
  ec=0; env -u HASKOKI_CONSUMER_TOPOLOGY "$BIN" "$SO" >"$DLOG" 2>&1 || ec=$?
  echo "direct exit: $base $ec"
  if [ "$ec" -ne 0 ]; then echo "--- direct log:"; cat "$DLOG"; fail "$base FAILED direct"; fi
  for entry in $DIRECT_ONLY; do
    if [ "${entry%%:*}" = "$base" ]; then
      echo "DIRECT-ONLY: $base (proxied leg skipped, see ${entry#*:})"
      archive_logs "$DLOG"
      return 0
    fi
  done
  echo "child argv: env HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT=$ENDPOINT PKCS11_PROXY_MECHANISMS=$TMPD/mechanisms-override.toml $BIN $SHIM_SO"
  ec=0; HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    PKCS11_PROXY_MECHANISMS="$TMPD/mechanisms-override.toml" \
    "$BIN" "$SHIM_SO" >"$PLOG" 2>&1 || ec=$?
  echo "proxied exit: $base $ec"
  if [ "$ec" -ne 0 ]; then echo "--- proxied log:"; cat "$PLOG"; fail "$base FAILED proxied"; fi
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
  archive_logs "$DLOG" "$PLOG" "$DNORM" "$PNORM" "$TMPD/$base.diff"
}

if [ -n "${1:-}" ]; then
  fail "usage: scripts/test-proxy-parity.sh"
fi

# Group R: all retained scenarios on the default backend.
start_daemon "$TMPD/backend.toml" "$TMPD/server.log"
for scen in $SCEN_LIST; do
  base="$(basename "$scen" .c)"
  if [ "$base" = "consumer_certificates" ]; then
    continue
  fi
  run_parity "$base"
done
cleanup

# Group C: the certificate scenario only, once per storage mode, each
# with a fresh daemon on its own catalog backend.
CERT_MODE=""
for CERT_MODE in $HASKOKI_PARITY_STORAGE; do
  write_cert_backend "$CERT_MODE" "$TMPD/backend-cert-$CERT_MODE.toml"
  start_daemon "$TMPD/backend-cert-$CERT_MODE.toml" "$TMPD/server-cert-$CERT_MODE.log"
  run_parity consumer_certificates
  cleanup
done

echo "PASS: test-proxy-parity.sh (direct/proxy parity)"
