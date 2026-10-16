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
# 2026-10-15 (#17, v0.5 WP11): consumer_policy_metadata is no longer
# DIRECT_ONLY. Group P (after group R) runs it proxied: each policy
# scenario gets its own daemon started on the config the consumer prints
# via --print-config (the driver holds no TOML for it), the direct and
# proxied transcripts are diffed, and a NEGATIVE-CONTROL leg proves the
# comparison can fail (limit2-null against the unconfigured global
# backend must exit 3 with policy:backend-mismatch). The three PIN
# refusal scenarios have no proxied session shape; their proxied
# equivalent is a STARTUP-REFUSAL (the daemon must exit nonzero without
# ever accepting on the port). stop_daemon verifies each daemon is gone
# and the port free before the next leg; a self-check at startup proves
# the squatter guard refuses a pre-bound port.
#
# Usage:
#   scripts/test-proxy-parity.sh             # full parity (must PASS)
#   HASKOKI_PARITY_GROUPS="P" scripts/test-proxy-parity.sh
#                                           # development filter: run only
#                                           # the listed groups (R C P,
#                                           # default all; an unknown name
#                                           # fails). Prints PARTIAL and
#                                           # exits 1 unless
#                                           # HASKOKI_PARITY_ALLOW_PARTIAL=1;
#                                           # never use it for evidence
#   HASKOKI_PARITY_STORAGE=memory scripts/test-proxy-parity.sh
#                                           # narrows the certificate
#                                           # storage cells; any set other
#                                           # than memory+sqlite is PARTIAL
#                                           # (same exit rule as GROUPS)
#   HASKOKI_PARITY_REPROBE=1 scripts/test-proxy-parity.sh
#                                           # also re-probes excluded legs;
#                                           # ends in REPROBE-RUN, not PASS
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
# Group P owns consumer_policy_metadata (per-scenario configs); the
# generic group-R list excludes it, and the guard below fails if both
# groups would run it.
RUN_LIST=$(printf '%s\n' "$SCEN_LIST" | grep -vx 'tests/c/consumer_policy_metadata.c')
POLICY_SCEN=tests/c/consumer_policy_metadata.c
[ -f "$POLICY_SCEN" ] || fail "policy consumer missing"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx "$POLICY_SCEN")" -eq 1 ] \
  || fail "policy consumer must occur exactly once"
[ "$(printf '%s\n' "$RUN_LIST" | grep -cx "$POLICY_SCEN")" -eq 0 ] \
  || fail "consumer_policy_metadata must not run in both the generic list and group P"
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
# consumer_certificates:visibility (R5: MOVED 26->27; fix round 1,
# 2026-10-16: REMOVED -- the failure was a driver artifact: one shared
# daemon served the whole version matrix with a fixed "vis-private"
# TOKEN label, so objects left by 2.40 made the 3.0+ census find
# matches=2. With a fresh daemon (and sqlite directory) per version and
# storage the leg passes in all four versions x both storages and is
# gated; the shared-daemon attribution to #27 was wrong).
# consumer_certificates:restart:sqlite and :restart:memory (both
# re-probed 2026-10-16, after the storage-attribute fix, error in all
# four versions; see docs/proxy-exclusions.md). The old sqlite failure,
# restart-token-refind (0 matches proxied, 1 direct), was a Haskoki
# defect, now fixed: objects created without CKA_PRIVATE read
# CKR_ATTRIBUTE_TYPE_INVALID for it, and the proxy hides objects of
# unknown privacy from a logged-out context it did not mint them in.
# They now read CKA_PRIVATE false and the re-find passes proxied. What
# remains is proxy behavior:
#   sqlite: restart-stale-fault rv=0x150 expected=0x82. The proxy's
#     virtual object handles are per client context and restart at 1,
#     so the pre-restart handle names the first object found after
#     re-initialize instead of faulting.
#   memory: restart-memory-volatile matches=1 expected=0. The daemon
#     never finalizes the backend on a client C_Finalize, so the
#     memory-store object outlives the client restart. The leg passed
#     before only because the CKA_PRIVATE defect hid that object.
# Upstream issue 27 is the reference for both: closed by design on
# 2026-10-05 (backend objects outlive a client C_Finalize; per-client
# teardown, which covers the per-context handles, deferred to v0.3):
# https://github.com/mingulov/pkcs11-proxy-ng/issues/27.
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
consumer_certificates:restart:sqlite:https://github.com/mingulov/pkcs11-proxy-ng/issues/27
consumer_certificates:restart:memory:https://github.com/mingulov/pkcs11-proxy-ng/issues/27"
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
        2.40:*|3.0:*|3.1:*|3.2:*|memory:*|sqlite:*)
          # version-qualified, or (certificate legs only) storage-
          # qualified: leg:memory:URL / leg:sqlite:URL
          dqual="${durl%%:*}"
          durl="${durl#*:}"
          case "$durl" in
            https://?*) ;;
            *) fail "malformed direct-only entry" ;;
          esac
          case "$dqual" in
            memory|sqlite)
              [ "$dname" = "consumer_certificates" ] \
                || fail "malformed direct-only entry"
              ;;
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
  # $1 = storage mode, $2 = output path, $3 = state tag. Every tag gets
  # its OWN empty sqlite directory, so a daemon never inherits objects
  # from another version or from a re-probe (fresh state per daemon).
  if [ "$1" = "sqlite" ]; then
    rm -rf "$TMPD/cert-db-$1-$3" || fail "cannot clear $TMPD/cert-db-$1-$3"
    mkdir -p "$TMPD/cert-db-$1-$3" || fail "cannot create $TMPD/cert-db-$1-$3"
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
    echo "path = \"$TMPD/cert-db-$1-$3/tokens.db\"" >> "$2" \
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
port_open() {
  bash -c "echo > /dev/tcp/127.0.0.1/$PROXY_PORT" 2>/dev/null
}
pid_alive() {
  # live and not a zombie (an unreaped child still answers kill -0)
  [ -r "/proc/$1/stat" ] || return 1
  st=$(sed -e 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -c1)
  [ -n "$st" ] && [ "$st" != "Z" ]
}
# EXIT-trap cleanup: best effort, never fails.
# EXTRA_PIDS tracks daemons started outside start_daemon (refusal
# checks, the squatter self-check) so an interrupt cannot leave one
# behind to trip the next run's squatter guard.
EXTRA_PIDS=""
cleanup() {
  if [ -n "${SRV:-}" ]; then
    kill $SRV 2>/dev/null || true
    wait $SRV 2>/dev/null || true
    SRV=""
  fi
  if [ -n "${EXTRA_PIDS:-}" ]; then
    kill -KILL $EXTRA_PIDS 2>/dev/null || true
    wait $EXTRA_PIDS 2>/dev/null || true
    EXTRA_PIDS=""
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
# Verified stop (#17): TERM, wait up to 10 s, then KILL; the pid must be
# gone and the port must refuse connections before the next leg starts.
# The log is kept.
stop_daemon() {
  [ -n "${SRV:-}" ] || fail "stop_daemon: no live daemon recorded"
  _pid=$SRV
  kill "$_pid" 2>/dev/null || true
  _i=0
  while pid_alive "$_pid" && [ "$_i" -lt 10 ]; do
    sleep 1
    _i=$((_i + 1))
  done
  if pid_alive "$_pid"; then
    kill -KILL "$_pid" 2>/dev/null || true
    _i=0
    while pid_alive "$_pid" && [ "$_i" -lt 10 ]; do
      sleep 1
      _i=$((_i + 1))
    done
  fi
  wait "$_pid" 2>/dev/null || true
  SRV=""
  if kill -0 "$_pid" 2>/dev/null; then
    fail "daemon pid $_pid still alive after stop"
  fi
  # The daemon may hand the port to a lingering child; give the kernel
  # a moment to drop the listener, then require a refused connect.
  _i=0
  while port_open && [ "$_i" -lt 5 ]; do
    sleep 1
    _i=$((_i + 1))
  done
  if port_open; then
    fail "port $PROXY_PORT still bound after stop"
  fi
  echo "proxy daemon stopped (pid $_pid)"
}
start_daemon() {
  # $1 = backend.toml, $2 = server log
  # Squatter guard: a stale manual daemon on our port would answer the
  # readiness probe below and silently hijack the run (observed: a whole
  # parity run executed against a polluted hand-started daemon).
  if bash -c "echo > /dev/tcp/127.0.0.1/$PROXY_PORT" 2>/dev/null; then
    fail "port $PROXY_PORT already bound (stale daemon squatting?)"
  fi
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
    # The accepting socket must be OURS: the daemon logs "listening on
    # tcp" only after its own bind succeeded, and it must still be alive
    # (a squatter holding the port satisfies the TCP probe alone).
    if port_open && grep -q 'listening on tcp' "$SERVER_LOG" 2>/dev/null \
        && pid_alive "$SRV"; then
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

# Startup-refusal check (#17): the daemon, started on a config the
# backend must refuse, has to exit nonzero within 30 s, without the port
# ever accepting, and its log has to show the backend load failure.
# $1 = backend.toml, $2 = server log, $3 = scenario label
start_daemon_expect_refusal() {
  if port_open; then
    fail "port $PROXY_PORT already bound (stale daemon squatting?)"
  fi
  RUST_LOG=info HASKOKI_CONFIG="$1" "$SERVER_BIN" "$TMPD/proxy.toml" \
    >"$2" 2>&1 &
  _rpid=$!
  EXTRA_PIDS="$EXTRA_PIDS $_rpid"
  _i=0
  _gone=0
  while [ "$_i" -lt 30 ]; do
    if port_open; then
      kill -KILL "$_rpid" 2>/dev/null || true
      wait "$_rpid" 2>/dev/null || true
      echo "--- daemon log:"; cat "$2"
      fail "STARTUP-REFUSAL: $3: daemon accepted on port $PROXY_PORT"
    fi
    if ! pid_alive "$_rpid"; then
      _gone=1
      break
    fi
    _i=$((_i + 1))
    sleep 1
  done
  if [ "$_gone" -ne 1 ]; then
    kill -KILL "$_rpid" 2>/dev/null || true
    wait "$_rpid" 2>/dev/null || true
    echo "--- daemon log:"; cat "$2"
    fail "STARTUP-REFUSAL: $3: daemon neither exited nor accepted within 30s"
  fi
  _rc=0
  wait "$_rpid" 2>/dev/null || _rc=$?
  EXTRA_PIDS=""
  if [ "$_rc" -eq 0 ]; then
    echo "--- daemon log:"; cat "$2"
    fail "STARTUP-REFUSAL: $3: daemon exited 0 (must refuse nonzero)"
  fi
  if port_open; then
    fail "STARTUP-REFUSAL: $3: port $PROXY_PORT accepting after refusal"
  fi
  if grep -q 'listening on tcp' "$2"; then
    echo "--- daemon log:"; cat "$2"
    fail "STARTUP-REFUSAL: $3: log shows the listener came up"
  fi
  if ! grep -q "$REFUSAL_PATTERN" "$2"; then
    echo "--- daemon log:"; cat "$2"
    fail "STARTUP-REFUSAL: $3: log lacks the backend load error ($REFUSAL_PATTERN)"
  fi
  echo "STARTUP-REFUSAL: $3 (daemon exit $_rc, NOT_SERVING logged, never listened)"
}

# expect_fail <desc> <pattern> <cmd...>: run cmd in a subshell; it MUST
# exit nonzero AND its output MUST match the grep pattern (a driver
# fail() with the named cause is the expected outcome; any other failure
# would make the check vacuous).
expect_fail() {
  _desc=$1; _pat=$2; shift 2
  _out=$( ( "$@" ) 2>&1 ); _ec=$?
  if [ "$_ec" -eq 0 ]; then
    echo "$_out"
    fail "expected failure did not occur: $_desc"
  fi
  if ! printf '%s\n' "$_out" | grep -q -- "$_pat"; then
    echo "$_out"
    fail "expected failure for the wrong reason (want /$_pat/): $_desc"
  fi
  echo "expected failure observed: $_desc"
}

# Self-check of the squatter guard (runs before any group): with a
# throwaway listener on the port (the daemon itself on the global
# backend, started outside start_daemon), start_daemon must refuse.
selfcheck_squatter() {
  RUST_LOG=info HASKOKI_CONFIG="$TMPD/backend.toml" "$SERVER_BIN" \
    "$TMPD/proxy.toml" >"$TMPD/server-squatter.log" 2>&1 &
  _sq=$!
  EXTRA_PIDS="$EXTRA_PIDS $_sq"
  _i=0
  while ! port_open && [ "$_i" -lt 30 ]; do
    pid_alive "$_sq" || break
    sleep 1
    _i=$((_i + 1))
  done
  port_open || { kill -KILL "$_sq" 2>/dev/null; cat "$TMPD/server-squatter.log"; fail "self-check listener did not bind"; }
  expect_fail "start_daemon refuses a pre-bound port" "already bound" \
    start_daemon "$TMPD/backend.toml" "$TMPD/server-selfcheck.log"
  kill "$_sq" 2>/dev/null || true
  _i=0
  while pid_alive "$_sq" && [ "$_i" -lt 10 ]; do
    sleep 1
    _i=$((_i + 1))
  done
  pid_alive "$_sq" && kill -KILL "$_sq" 2>/dev/null
  wait "$_sq" 2>/dev/null || true
  EXTRA_PIDS=""
  _i=0
  while port_open && [ "$_i" -lt 5 ]; do
    sleep 1
    _i=$((_i + 1))
  done
  port_open && fail "self-check listener still bound"
  echo "SELF-CHECK: squatter guard refuses a pre-bound port"
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

# Opt-in re-probe (HASKOKI_PARITY_REPROBE=1, WP11): an excluded proxied
# leg is queued instead of skipped, and flush_reprobes runs the queue on a
# fresh daemon (same backend config) after the group's gate daemon has
# stopped, so a re-probe never shares state with a gated leg (observed:
# re-probing consumer_certificates:visibility on the live cert daemon
# left objects that failed the next atomicity census). Each outcome goes
# to $ARTIFACTS/reprobe.tsv: the entry with the version and storage it
# ran under appended after '@' (when the entry leaves them open), the
# see-URL, pass|diff|error:<rc>, the diff sha256 and the daemon sha256.
# A re-probe never fails the run; without the variable the excluded leg
# is skipped exactly as before.
REPROBE_QUEUE="$TMPD/reprobe.queue"
: > "$REPROBE_QUEUE"
reprobe() {
  # $1 = entry label, $2 = see-URL, $3 = direct log, $4 = proxied log,
  # remaining = the proxied child argv (no argument contains whitespace)
  [ "${HASKOKI_PARITY_REPROBE:-}" = "1" ] || return 0
  # The queue flattens argv through a tab-separated file and unquoted
  # word splitting: refuse any argument that would not survive that.
  for _a in "$@"; do
    case "$_a" in
      *[!A-Za-z0-9_./:@=,+-]*|"") fail "reprobe: unsafe argument for queue: '$_a'" ;;
    esac
  done
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$(shift 4; echo "$*")" \
    >> "$REPROBE_QUEUE"
  echo "REPROBE: $1 queued"
}
run_reprobe() {
  RL="$1"; RU="$2"; RD="$3"; RP="$4"; shift 4
  rc=0; HASKOKI_CONSUMER_TOPOLOGY=proxy PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    PKCS11_PROXY_MECHANISMS="$TMPD/mechanisms-override.toml" \
    timeout -s KILL 300 "$@" >"$RP" 2>&1 || rc=$?
  normalize "$RD" "$RP.reprobe-direct.norm"
  normalize "$RP" "$RP.reprobe-proxied.norm"
  if [ "$rc" -ne 0 ]; then
    res="error:$rc"
  elif diff -u "$RP.reprobe-direct.norm" "$RP.reprobe-proxied.norm" > "$RP.reprobe.diff"; then
    res="pass"
  else
    res="diff"
  fi
  [ -f "$RP.reprobe.diff" ] || : > "$RP.reprobe.diff"
  dsha=$(sha256sum < "$RP.reprobe.diff" | cut -c1-64)
  printf '%s\t%s\t%s\t%s\t%s\n' "$RL" "$RU" "$res" "$dsha" \
    "$(sha256sum < "$SERVER_BIN" | cut -c1-64)" >> "$ARTIFACTS/reprobe.tsv"
  echo "REPROBE: $RL -> $res"
  archive_logs "$RP" "$RP.reprobe.diff"
}
flush_reprobes() {
  # $1 = backend.toml of the group's gate daemon, $2 = server log base,
  # $3 = optional command (eval) that rewrites $1 with fresh state.
  # Every queued leg gets its OWN fresh daemon: a re-probe must not see
  # objects left by another version or leg (that run-order effect was
  # once mistaken for an upstream defect).
  [ -s "$REPROBE_QUEUE" ] || return 0
  _n=0
  while IFS="$(printf '\t')" read -r ql qu qd qp qargv; do
    _n=$((_n + 1))
    if [ -n "${3:-}" ]; then eval "$3"; fi
    start_daemon "$1" "$2.$_n.log"
    # shellcheck disable=SC2086
    run_reprobe "$ql" "$qu" "$qd" "$qp" $qargv
    stop_daemon
  done < "$REPROBE_QUEUE"
  : > "$REPROBE_QUEUE"
}

run_parity_cert_leg() {
  # $1 = version, $2 = leg; $CERT_MODE is the LIVE daemon's storage mode
  V="$1"; L="$2"; M="$CERT_MODE"
  D="$TMPD/cert-$M/$V-$L"
  # Fresh dir per leg per run: legs leave created objects behind and
  # TMPD persists across driver runs, so a reused dir double-counts
  # shelf state (observed: visibility finds 2 on rerun, expects 1).
  rm -rf "$D" || fail "cannot clear $D"
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
      "consumer_certificates:$L:$M:"*)
        echo "DIRECT-ONLY: consumer_certificates:$L:$M (proxied leg skipped, see ${entry#consumer_certificates:$L:$M:})"
        reprobe "consumer_certificates:$L:$M@$V" "${entry#consumer_certificates:$L:$M:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --storage "$M" --leg "$L" --directory "$D"
        archive_logs "$DLOG"
        return 0
        ;;
      "consumer_certificates:$L:$V:"*)
        echo "DIRECT-ONLY: consumer_certificates:$L:$V (proxied leg skipped, see ${entry#consumer_certificates:$L:$V:})"
        reprobe "consumer_certificates:$L:$V@$M" "${entry#consumer_certificates:$L:$V:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --storage "$M" --leg "$L" --directory "$D"
        archive_logs "$DLOG"
        return 0
        ;;
      "consumer_certificates:$L:"*)
        case "${entry#consumer_certificates:$L:}" in
          2.40:*|3.0:*|3.1:*|3.2:*|memory:*|sqlite:*)
            # Version- or storage-qualified entry for another version
            # or storage: this run proceeds.
            ;;
          https://?*)
            echo "DIRECT-ONLY: consumer_certificates:$L (proxied leg skipped, see ${entry#consumer_certificates:$L:})"
            reprobe "consumer_certificates:$L@$V/$M" "${entry#consumer_certificates:$L:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --storage "$M" --leg "$L" --directory "$D"
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
        reprobe "consumer_certificates@$V/$M" "${entry#consumer_certificates:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --storage "$M" --leg "$L" --directory "$D"
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
        reprobe "$B:$L:$V" "${entry#$B:$L:$V:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --legs "$L"
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
            reprobe "$B:$L@$V" "${entry#$B:$L:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --legs "$L"
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
        reprobe "$B@$V" "${entry#$B:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO" --version "$V" --legs "$L"
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
    for V in $CERT_V; do
      for L in $CERT_L; do
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
      reprobe "$base" "${entry#*:}" "$DLOG" "$PLOG" "$BIN" "$SHIM_SO"
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

# HASKOKI_PARITY_GROUPS (development only) selects a subset of the
# groups R C P. Unknown tokens fail; any subset ends in a PARTIAL line
# and a nonzero exit (unless HASKOKI_PARITY_ALLOW_PARTIAL=1), never the
# full PASS line.
GROUPS_RUN="${HASKOKI_PARITY_GROUPS:-R C P}"
[ -n "$(echo $GROUPS_RUN)" ] || fail "HASKOKI_PARITY_GROUPS is empty (valid: R C P)"
for _g in $GROUPS_RUN; do
  case "$_g" in
    R|C|P) ;;
    *) fail "unknown parity group '$_g' in HASKOKI_PARITY_GROUPS (valid: R C P)" ;;
  esac
done
GROUPS_NORM=$(for _g in R C P; do group_has=0; for _x in $GROUPS_RUN; do [ "$_x" = "$_g" ] && group_has=1; done; [ "$group_has" -eq 1 ] && printf '%s ' "$_g"; done)
GROUPS_NORM="${GROUPS_NORM% }"
group_on() {
  case " $GROUPS_RUN " in *" $1 "*) return 0 ;; esac
  return 1
}

selfcheck_squatter

# Group R: all retained scenarios on the default backend, each with a
# FRESH daemon: token-auth/object state (e.g. roundtrip's deliberate
# SO lockout) must not leak across scenarios. Direct legs each get a
# fresh in-process backend, so proxied legs get a fresh daemon each.
# consumer_policy_metadata is excluded here (group P owns it).
if group_on R; then
for scen in $RUN_LIST; do
  base="$(basename "$scen" .c)"
  if [ "$base" = "consumer_certificates" ]; then
    continue
  fi
  start_daemon "$TMPD/backend.toml" "$TMPD/server-$base.log"
  run_parity "$base"
  stop_daemon
  flush_reprobes "$TMPD/backend.toml" "$TMPD/server-$base-reprobe"
done
fi

# Group C: the certificate scenario only, once per storage mode, each
# with a fresh daemon on its own catalog backend.
CERT_MODE=""
if group_on C; then
# One fresh daemon (own sqlite directory) per storage, version AND leg,
# mirroring the direct side where every leg gets a fresh store: legs
# leave objects behind (visibility, create), and the atomicity census
# counts every object on the token.
for CERT_MODE in $HASKOKI_PARITY_STORAGE; do
  for CERT_V in 2.40 3.0 3.1 3.2; do
    for CERT_L in $CERT_LEGS; do
      write_cert_backend "$CERT_MODE" "$TMPD/backend-cert-$CERT_MODE.toml" "$CERT_V-$CERT_L"
      start_daemon "$TMPD/backend-cert-$CERT_MODE.toml" "$TMPD/server-cert-$CERT_MODE-$CERT_V-$CERT_L.log"
      run_parity consumer_certificates
      stop_daemon
    done
  done
  write_cert_backend "$CERT_MODE" "$TMPD/backend-cert-$CERT_MODE.toml" rp
  flush_reprobes "$TMPD/backend-cert-$CERT_MODE.toml" "$TMPD/server-cert-$CERT_MODE-reprobe" \
    'write_cert_backend "$CERT_MODE" "$TMPD/backend-cert-$CERT_MODE.toml" rp'
done
fi

# Group P (#17): policy/metadata scenarios, one daemon per scenario on
# the config the consumer itself prints.
run_policy_child_direct() {
  # $1 = scenario; sets PDLOG/PDNORM
  ec=0; env -u HASKOKI_CONSUMER_TOPOLOGY -u HASKOKI_CONFIG \
    "$PBIN" "$SO" "$1" >"$PDLOG" 2>&1 || ec=$?
  echo "direct exit: consumer_policy_metadata:$1 $ec"
  if [ "$ec" -ne 0 ]; then echo "--- direct log:"; cat "$PDLOG"; fail "consumer_policy_metadata:$1 FAILED direct"; fi
}
run_policy_child_proxied() {
  # $1 = scenario, $2 = log; sets ec
  ec=0; env -u HASKOKI_CONFIG HASKOKI_CONSUMER_TOPOLOGY=proxy \
    PKCS11_PROXY_ENDPOINT="$ENDPOINT" \
    PKCS11_PROXY_MECHANISMS="$TMPD/mechanisms-override.toml" \
    "$PBIN" "$SHIM_SO" "$1" >"$2" 2>&1 || ec=$?
  echo "proxied exit: consumer_policy_metadata:$1 $ec"
}
if group_on P; then
PBIN="$TMPD/consumer_policy_metadata"
# The pinned daemon prints no backend error text: a backend that fails
# to load exits 70 after logging only this health line (observed on
# the pinned pair); a healthy start logs "listening on tcp" instead.
REFUSAL_PATTERN="Health status: NOT_SERVING"

# 1. Negative controls: each proxied child, run against a daemon whose
# config differs in exactly the property the scenario asserts, must be
# refused with the named cause. They run before the configured legs and
# bind every configured property to its config: session limit
# (limit2-null), token count and labels (multitoken), token catalog (pin)
# and the PIN (pin, right catalog but another demo user PIN).
# policy_negctl <scenario> <daemon-config> <exit> <fixed-line-regex> <desc>
policy_negctl() {
  _nc="$TMPD/consumer_policy_metadata-negctl-$1-$5.proxied.log"
  echo "--- parity: consumer_policy_metadata negative control: $1 vs $5"
  start_daemon "$2" "$TMPD/server-policy-negctl-$1-$5.log"
  run_policy_child_proxied "$1" "$_nc"
  if [ "$ec" -ne "$3" ] || ! grep -q "$4" "$_nc"; then
    echo "--- proxied log:"; cat "$_nc"
    fail "negative control: $1 against $5 not refused as expected (exit $ec, want $3 /$4/)"
  fi
  stop_daemon
  archive_logs "$_nc"
  echo "NEGATIVE-CONTROL: policy $1 vs $5 refused"
}
policy_negctl limit2-null "$TMPD/backend.toml" 3 \
  '^policy:backend-mismatch max want=2 got=1024$' unconfigured-daemon
policy_negctl multitoken "$TMPD/backend.toml" 3 \
  '^policy:backend-mismatch slots want=2 got=1$' unconfigured-daemon
policy_negctl pin "$TMPD/backend.toml" 3 \
  '^policy:backend-mismatch slots want=2 got=1$' unconfigured-daemon
"$PBIN" "$SO" --print-config pin >"$TMPD/policy-pin-wrongpin.toml" \
  || fail "cannot print config for pin"
sed -e 's/^user_pins = .*/user_pins = ["1234", "3210"]/' "$TMPD/policy-pin-wrongpin.toml" \
  >"$TMPD/policy-pin-wrongpin2.toml"
cmp -s "$TMPD/policy-pin-wrongpin.toml" "$TMPD/policy-pin-wrongpin2.toml" \
  && fail "wrong-PIN control config equals the pin config"
policy_negctl pin "$TMPD/policy-pin-wrongpin2.toml" 1 \
  '^FAIL .*pin correct user login ok' wrong-user-pin

# 2. Configured parity legs.
for pscen in limit2-null limit2-os limit2-app multitoken pin; do
  PCFG="$TMPD/policy-$pscen.toml"
  PDLOG="$TMPD/consumer_policy_metadata-$pscen.direct.log"
  PPLOG="$TMPD/consumer_policy_metadata-$pscen.proxied.log"
  PDNORM="$TMPD/consumer_policy_metadata-$pscen.direct.norm"
  PPNORM="$TMPD/consumer_policy_metadata-$pscen.proxied.norm"
  echo "--- parity: consumer_policy_metadata:$pscen"
  "$PBIN" "$SO" --print-config "$pscen" >"$PCFG" || fail "cannot print config for $pscen"
  [ -s "$PCFG" ] || fail "empty config for $pscen"
  run_policy_child_direct "$pscen"
  start_daemon "$PCFG" "$TMPD/server-policy-$pscen.log"
  run_policy_child_proxied "$pscen" "$PPLOG"
  if [ "$ec" -ne 0 ]; then echo "--- proxied log:"; cat "$PPLOG"; fail "consumer_policy_metadata:$pscen FAILED proxied"; fi
  seed_mutate "$PPLOG"
  normalize "$PDLOG" "$PDNORM"
  normalize "$PPLOG" "$PPNORM"
  if ! diff -u "$PDNORM" "$PPNORM" > "$TMPD/consumer_policy_metadata-$pscen.diff"; then
    echo "PARITY DIVERGENCE in consumer_policy_metadata:$pscen:"
    cat "$TMPD/consumer_policy_metadata-$pscen.diff"
    echo "--- full direct log:"; cat "$PDLOG"
    echo "--- full proxied log:"; cat "$PPLOG"
    fail "consumer_policy_metadata:$pscen: forwarded-call transcripts differ direct-vs-proxied"
  fi
  echo "parity holds: consumer_policy_metadata:$pscen ($(wc -l < "$PDNORM") forwarded lines identical)"
  stop_daemon
  archive_logs "$PDLOG" "$PPLOG" "$PDNORM" "$PPNORM" "$TMPD/consumer_policy_metadata-$pscen.diff" "$TMPD/server-policy-$pscen.log"
done

# 3. PIN-refusal scenarios: direct refusal assertions, proxied
# equivalent = daemon startup refusal.
for pscen in pin-short pin-empty pin-long; do
  PCFG="$TMPD/policy-$pscen.toml"
  PDLOG="$TMPD/consumer_policy_metadata-$pscen.direct.log"
  echo "--- parity: consumer_policy_metadata:$pscen (startup refusal)"
  "$PBIN" "$SO" --print-config "$pscen" >"$PCFG" || fail "cannot print config for $pscen"
  [ -s "$PCFG" ] || fail "empty config for $pscen"
  run_policy_child_direct "$pscen"
  start_daemon_expect_refusal "$PCFG" "$TMPD/server-policy-$pscen.log" "$pscen"
  archive_logs "$PDLOG" "$TMPD/server-policy-$pscen.log"
done
fi

# Final line: only a complete default run prints the PASS line that
# evidence is quoted from. A narrowed storage set is partial too: it
# drops the other storage's certificate cells and exclusion skips.
STORAGE_NORM=$(printf '%s\n' $HASKOKI_PARITY_STORAGE | sort -u | tr '\n' ' ' | sed 's/ $//')
if [ "$GROUPS_NORM" != "R C P" ] || [ "$STORAGE_NORM" != "memory sqlite" ]; then
  echo "PARTIAL: test-proxy-parity.sh groups run: $GROUPS_NORM, storage: $STORAGE_NORM (not a gate result; full run needs R C P with memory sqlite)"
  [ "${HASKOKI_PARITY_ALLOW_PARTIAL:-0}" = "1" ] || exit 1
  exit 0
fi
if [ "${HASKOKI_PARITY_REPROBE:-}" = "1" ]; then
  echo "REPROBE-RUN: test-proxy-parity.sh groups R C P passed with re-probes enabled (reprobe.tsv in $ARTIFACTS; not a gate record)"
  exit 0
fi
echo "PASS: test-proxy-parity.sh (direct/proxy parity)"
