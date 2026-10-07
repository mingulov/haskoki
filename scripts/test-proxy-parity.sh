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
# mechanism (merged shim catalog, derive shape gate, shim-side
# session validation, absent vendor trampolines).
#
# Proxy provenance (external binaries, never built into the repo):
#   source: https://github.com/mingulov/pkcs11-proxy-ng
#   commit: 1ed7cc15c838de2e56ba03ac34f426847ffce049 (tag v0.2.2,
#             "Record v0.2.2 quality receipt"; annotated-tag object
#             e500cec9; R9 re-pin — v0.2.0 superseded: v0.2.2 fixes
#             upstream #35 (logout DATA loss), #36 (cert-find hole),
#             #37 (daemon death on message params), and #39
#             (IV-shaped message-init 0x71, unclaimed upstream).
#             Behavior notes (v0.2.1-origin, kept in v0.2.2): the
#             live shim catalog merges the backend-published 3.1
#             (4 entries, functional); init params forward to the
#             backend (backend codes surface); derive garbage fails
#             closed 0x71 before key-type/args checks (3 known
#             divergences, branched in consumer_roundtrip).
#             v0.2.1 was attempted and REJECTED (upstream #35/#36/#37;
#             v0.2.0 history: fixed PBE OUT-IV writeback,
#             embedded-handle mapping, unknown-attr forwarding, and
#             NULL-input normalization over a48b60b).
#   built:  throwaway rust:1.94-bookworm container,
#             apt-get install protobuf-compiler && cargo build --release --locked
#           (effective toolchain 1.98.1 via the repo's
#           rust-toolchain.toml in both the canonical build and the
#           demo image proxy stage)
#           artifacts: pkcs11-proxy-ng (daemon) +
#             libpkcs11_proxy_ng_shim.so (loadable shim)
#   env:    HASKOKI_PROXY_DIR (default /opt/pkcs11-proxy-ng) must hold
#           both artifacts; HASKOKI_PROXY_PORT (default 17512) selects
#           the loopback listener.
#
# Canonical build (the ONLY authoritative hashes):
#   daemon sha256:
#     91d9ccba8e579891fb5a8815f66518baef0a757bd9a2563097983ca9d056385b  pkcs11-proxy-ng
#   shim sha256:
#     87eb3f651c82de637e30666f305fae540375680bc754cf76249e17b6e7cb1d75  libpkcs11_proxy_ng_shim.so
#   Cargo.lock sha256 (of the source tree at the commit above):
#     5452b6bd6ab47d72e8172a04a8f8a72460dabc17f66ced110b930f6d5d75b7d3  Cargo.lock
#   repro: from a pristine checkout of the source above at the commit
#   above (no target/ dir), run the pinned-toolchain recipe:
#     timeout -s KILL 2400 docker run --rm --network host \
#       -v <src>:/src -w /src rust:1.94-bookworm \
#       bash -c 'apt-get update -qq && apt-get install -y -qq \
#         protobuf-compiler && cargo build --release --locked'
#     sha256sum target/release/pkcs11-proxy-ng \
#       target/release/libpkcs11_proxy_ng_shim.so
#   The two hashes MUST match the pair above (recorded 2026-10-06
#   from a pristine v0.2.2 build; byte-identity is re-verified by
#   the demo image proxy stage, which rebuilds from the same commit
#   SHA + locked recipe and asserts commit, Cargo.lock, and this
#   pair via PROXY_CANON_* — fail closed on ANY mismatch, FINAL-35).
#
# Historical /tmp builds (a past review concern): EIGHT
# divergent pairs were found under /tmp (five hash-distinct).
# None carried recorded provenance, so none was authoritative;
# all were deleted during review. Any /tmp pair found later
# MUST be rebuilt from the pinned commit + recipe and re-pinned
# here before use; unrecorded binaries are never authoritative.
#
# Residual tree (recorded during an a48b60b-era review, SUPERSEDED
# by the v0.2.0 re-pin above): /tmp/pkcs11-proxy-ng/target/release/
# held a build at a48b60b (clean checkout) whose artifacts were
# byte-identical to the THEN-canonical a48b60b pair (daemon
# 260cb245…, shim 8ea85073… — NOT the v0.2.0 pair above).
#
# Sensitivity proof (a parity script that cannot fail is theater):
#   HASKOKI_PARITY_SEED_MISMATCH=1 mutates one compared
#   deterministic result on the proxied side BEFORE normalization
#   (seed_mutate marks the first retained non-PASS line, which then
#   flows through the real normalize+diff path); the script MUST
#   fail and report the divergent call plus both outputs.
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

PROXY_COMMIT="1ed7cc15c838de2e56ba03ac34f426847ffce049"
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
[ -f tests/c/dual_routed.c ] || fail "dual consumer missing"
[ -f tests/c/recover_routed.c ] || fail "recover consumer missing"
[ -f tests/c/consumer_notifications_poll.c ] || fail "notifications polling consumer missing"
SCEN_LIST=$(
  for scen in tests/c/consumer_*.c tests/c/message_routed.c tests/c/async_routed.c tests/c/notifications_routed.c tests/c/consumer_certificates.c tests/c/dual_routed.c tests/c/recover_routed.c; do
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
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/dual_routed.c')" -eq 1 ] \
  || fail "dual consumer must occur exactly once"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/recover_routed.c')" -eq 1 ] \
  || fail "recover consumer must occur exactly once"
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
# six certificate legs (create/find/lifecycle/visibility/atomicity/restart),
# the three dual legs (route/equiv/neg), or the four recover legs
# (route/pkcs/flags/neg), and must belong to the named consumer.
# Per-version entries base:leg:version:upstream-issue-URL
# skip only that leg+version's proxied run; version is one of
# 2.40/3.0/3.1/3.2 (whole-leg and whole-basename entries keep working).
# message_routed (R9: raw-IV init now forwards, #39 fixed — leg stays
# for the remaining #23 defects: EncryptMessageNext IV repair /
# supply-at-end / replace-at-end plus the GCM KAT sweep, 5 fails).
# async_routed: fixed GetID/Join refusals; Complete source cannot preserve
# caller output bindings/capacity. Direct success is not transport parity.
# notifications_routed (R9: a48b60b deadlocked Finalize behind a
# parked native wait; v0.2.2 refuses blocking waits at daemon
# admission instead — fail-fast FUNCTION_NOT_SUPPORTED, zero native
# attempts, mutex dropped before the RPC — but a refusal is not
# transport: callback association and provider control are still
# not transported, so the quarantine stays).
# Valid empty polling remains parity-eligible in consumer_notifications_poll.
# dual_routed/recover_routed: per-(version,leg) runs with transcript diff.
# dual/recover :3.1 legs (R9: REMOVED on v0.2.2 — all hold: dual
# route/equiv/neg 64/148/13, recover route/pkcs/flags/neg
# 48/40/21/83 forwarded lines identical; backend-published 3.1 is
# functional, upstream #29 closed):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/29; T-M07 R1.
# dual_routed route+neg × 3.2 (R5: REMOVED on v0.2.0 — both hold,
# 191/140 forwarded lines identical; the a48b60b NULL out-length /
# NULL-part causes are fixed by the v0.2.0 NULL-handling rework):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/30; T-M07 R2.
# recover_routed neg × 2.40/3.0/3.2 (R5: REMOVED on v0.2.0 — holds,
# 83 forwarded lines identical per version; the :3.1 entry below now
# does real work instead of duplicating this one):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/31; T-M07 R3.
# Reproductions + 28-pair transcripts: task-m07/matrix receipt.
# consumer_certificates:lifecycle+atomicity (R5: SHRUNK on v0.2.0 to
# the :3.1 legs under issue 28 — 2.40/3.0/3.2 hold since v0.2.0
# forwards GAV instead of zeroing the caller canary buffer):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/26; T-C09 R8.
# consumer_certificates:visibility (R5: MOVED 26→27 — the canary
# holds; the leg fails on cross-version census matches=2: fixed
# "vis-private" TOKEN label + one shared memory-backend daemon for
# the whole version matrix, while direct gets a fresh store per
# leg; 2.40 passes only because it runs first, so per-version
# eligibility would enshrine run-order dependence — whole leg).
# consumer_certificates:restart: memory token objects survive client
# Finalize/Initialize through the proxy (direct drops them);
# https://github.com/mingulov/pkcs11-proxy-ng/issues/27; T-C09 R9.
# consumer_certificates:create+find+lifecycle+atomicity:3.1 (R9:
# REMOVED on v0.2.2 — all hold, 112/174/215/87 forwarded lines
# identical per version x storage; upstream #28 closed):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/28; T-C09 R10.
# consumer_certificates:find (R5: NEW whole-leg on v0.2.0 — find
# never returned CKO_CERTIFICATE; R9: REMOVED on v0.2.2 — upstream
# #36 fixed and closed, leg holds all versions x storages):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/36.
DIRECT_ONLY="message_routed:https://github.com/mingulov/pkcs11-proxy-ng/issues/23
async_routed:https://github.com/mingulov/pkcs11-proxy-ng/issues/24
notifications_routed:https://github.com/mingulov/pkcs11-proxy-ng/issues/25
consumer_certificates:visibility:https://github.com/mingulov/pkcs11-proxy-ng/issues/27
consumer_certificates:restart:https://github.com/mingulov/pkcs11-proxy-ng/issues/27"
for entry in $DIRECT_ONLY; do
  dname="${entry%%:*}"; durl="${entry#*:}"
  [ -n "$durl" ] && [ "$durl" != "$entry" ] \
    || fail "direct-only entry without issue URL: $entry"
  # Strict disposition grammar (T-C09 R12 C09-02): after the basename
  # strip, the remainder must be exactly a whole-basename URL, a
  # whole-leg leg:URL, or a version-qualified leg:version:URL.
  # The first token after the basename is the leg for leg entries
  # (dual legs route/equiv/neg, recover legs route/pkcs/flags/neg)
  # or the URL scheme for whole-basename entries; a leg entry on
  # any other consumer fails below.
  dleg="${durl%%:*}"
  case "$durl" in
    https://?*)
      ;;
    create:*|find:*|lifecycle:*|visibility:*|atomicity:*|restart:*|route:*|equiv:*|neg:*|pkcs:*|flags:*)
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
  case "$dleg" in
    https)
      ;;
    create|find|lifecycle|visibility|atomicity|restart)
      [ "$dname" = "consumer_certificates" ] \
        || fail "malformed direct-only entry"
      ;;
    route|equiv|neg|pkcs|flags)
      case "$dname:$dleg" in
        dual_routed:route|dual_routed:equiv|dual_routed:neg|recover_routed:route|recover_routed:pkcs|recover_routed:flags|recover_routed:neg)
          ;;
        *) fail "malformed direct-only entry" ;;
      esac
      ;;
    # Defense in depth (T-C09 R12 C09-02): unreachable
    # post-validation, which rejects malformed entries first.
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
DUAL_LEGS="${DUAL_LEGS:-route equiv neg}"
RECOVER_LEGS="${RECOVER_LEGS:-route pkcs flags neg}"
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
# [mechanisms] config_path (v0.2.0+): the daemon publishes its
# mechanism registry to the shim at connect (upstream 6cff550) and
# the shim installs the published registry OVER its seeded
# embedded+PKCS11_PROXY_MECHANISMS registry. A shim-side-only
# override is therefore silently dropped on v0.2.0: the same file
# must be served daemon-side or the non-embedded entries
# (0x1094/0x210C/0x403A) fall back to parameterless and IV/param
# calls fail PARAM_INVALID (R5: 19-fail baseline, 7 lines). The
# file itself is written below; the daemon reads it at startup.
cat > "$TMPD/proxy.toml" <<EOF
[backend]
module = "$SO"

[proxy]
mechanism_discovery = "transparent"
lease_seconds = 600
request_timeout_secs = 60
max_concurrent_backend_calls = 200
max_blocking_threads = 512

[mechanisms]
config_path = "$TMPD/mechanisms-override.toml"

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
# v0.2.0 notes (R5): embedded absorbed all of the above plus the
# RC2/DES-CFB8/SSL3-MAC/AES-GMAC/MAC_GENERAL/ECDH-wrap rows —
# only 0x1094/0x210C/0x403A still need this file. The absorbed
# rows stay (harmless duplication, keeps one file for both
# sides). v0.2.0 REQUIRES the two-sided wiring: the daemon
# publishes its registry and the shim installs it over the
# seeded one, so the SAME file is served daemon-side via the
# [mechanisms] config_path above; shim-side-only is silently
# dropped (upstream 6cff550).
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

seed_mutate() {
  # $1 = raw proxied log: flip one compared deterministic result
  # BEFORE normalization (negative control). Marks the first
  # retained non-PASS line (retained = survives normalize's drop
  # rules, so the mutation flows through the real processing
  # path). PASS trailers are excluded (normalize reduces them,
  # which would erase the marker). Fails loud when no retained
  # line exists — a scenario with nothing compared is vacuous.
  [ "${HASKOKI_PARITY_SEED_MISMATCH:-0}" = "1" ] || return 0
  if awk '!done && !/^(topology:|invent:|crypto:|routed:|PASS:)/ \
      { $0 = $0 " [SEED-MUTATED]"; done = 1 } { print }' \
      "$1" > "$1.seeded" && grep -q 'SEED-MUTATED' "$1.seeded"; then
    mv "$1.seeded" "$1"
    echo "SEEDED: mutated one retained result line pre-normalize"
  else
    rm -f "$1.seeded"
    fail "seeded control found no retained line to mutate in $1"
  fi
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
  seed_mutate "$PLOG"
  normalize "$DLOG" "$DNORM"
  normalize "$PLOG" "$PNORM"
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

run_parity_routed_leg() {
  # $1 = consumer base (dual_routed|recover_routed), $2 = version, $3 = leg
  B="$1"; V="$2"; L="$3"
  DLOG="$TMPD/$B-$V-$L.direct.log"
  PLOG="$TMPD/$B-$V-$L.proxied.log"
  DNORM="$TMPD/$B-$V-$L.direct.norm"
  PNORM="$TMPD/$B-$V-$L.proxied.norm"
  echo "--- parity leg: $B version=$V legs=$L"
  echo "child argv: env -u HASKOKI_CONSUMER_TOPOLOGY $BIN $SO --version $V --legs $L"
  ec=0; env -u HASKOKI_CONSUMER_TOPOLOGY "$BIN" "$SO" --version "$V" --legs "$L" >"$DLOG" 2>&1 || ec=$?
  echo "direct exit: $B:$V-$L $ec"
  if [ "$ec" -ne 0 ]; then echo "--- direct log:"; cat "$DLOG"; fail "$B:$L FAILED direct ($V)"; fi
  for entry in $DIRECT_ONLY; do
    case "$entry" in
      "$B:$L:$V:"*)
        echo "DIRECT-ONLY: $B:$L:$V (proxied leg skipped, see ${entry#$B:$L:$V:})"
        archive_logs "$DLOG"
        return 0
        ;;
      "$B:$L:"*)
        case "${entry#$B:$L:}" in
          2.40:*|3.0:*|3.1:*|3.2:*)
            # Version-qualified entry for another version: this run proceeds.
            ;;
          https://?*)
            echo "DIRECT-ONLY: $B:$L (proxied leg skipped, see ${entry#$B:$L:})"
            archive_logs "$DLOG"
            return 0
            ;;
          # Defense in depth (T-C09 R12 C09-02): unreachable
          # post-validation, which rejects malformed entries first.
          *) fail "malformed direct-only entry" ;;
        esac
        ;;
      "$B:http"*)
        echo "DIRECT-ONLY: $B (proxied leg skipped, see ${entry#$B:})"
        archive_logs "$DLOG"
        return 0
        ;;
    esac
  done
  echo "child argv: env HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT=$ENDPOINT PKCS11_PROXY_MECHANISMS=$TMPD/mechanisms-override.toml $BIN $SHIM_SO --version $V --legs $L"
  ec=0; HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    PKCS11_PROXY_MECHANISMS="$TMPD/mechanisms-override.toml" \
    "$BIN" "$SHIM_SO" --version "$V" --legs "$L" >"$PLOG" 2>&1 || ec=$?
  echo "proxied exit: $B:$V-$L $ec"
  if [ "$ec" -ne 0 ]; then echo "--- proxied log:"; cat "$PLOG"; fail "$B:$L FAILED proxied ($V)"; fi
  seed_mutate "$PLOG"
  normalize "$DLOG" "$DNORM"
  normalize "$PLOG" "$PNORM"
  if ! diff -u "$DNORM" "$PNORM" > "$TMPD/$B-$V-$L.diff"; then
    echo "PARITY DIVERGENCE in $B:$L ($V):"
    cat "$TMPD/$B-$V-$L.diff"
    echo "--- full direct log:"
    cat "$DLOG"
    echo "--- full proxied log:"
    cat "$PLOG"
    fail "$B:$L: forwarded-call transcripts differ direct-vs-proxied ($V)"
  fi
  echo "parity holds: $B:$L ($V, $(wc -l < "$DNORM") forwarded lines identical)"
  archive_logs "$DLOG" "$PLOG" "$DNORM" "$PNORM" "$TMPD/$B-$V-$L.diff"
}

run_parity() {
  # $1 = scenario base name
  base="$1"
  BIN="$TMPD/$base"
  if [ "$base" = "dual_routed" ] || [ "$base" = "recover_routed" ]; then
    echo "--- parity: $base (per-leg)"
    if [ "$base" = "dual_routed" ]; then
      LEGS="$DUAL_LEGS"
    else
      LEGS="$RECOVER_LEGS"
    fi
    for V in 2.40 3.0 3.1 3.2; do
      for L in $LEGS; do
        run_parity_routed_leg "$base" "$V" "$L"
      done
    done
    return 0
  fi
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
  seed_mutate "$PLOG"
  normalize "$DLOG" "$DNORM"
  normalize "$PLOG" "$PNORM"
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
