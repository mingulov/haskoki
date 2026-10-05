#!/bin/sh
# scripts/test-demo-image.sh -- demo image end-to-end driver (host side).
#
# Builds the self-contained demo image, then proves every entrypoint
# contract: expected tag/digest shape, demo verifications, check lanes
# (smoke/full x direct/proxy, all under --network none; direct
# byte-exact, proxy stable-core + classified flaky), compare diff
# (under --network none; stable-core + classified flaky), help texts +
# usage-error matrix + examples + JSON purity, arbitrary-UID rerun,
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

# Stable-core + classified-flaky assertion (R3d disposition for the
# proxy-lane timing flake; evidence in task-R3-report.md section 9.8).
# $1 = label, $2 = expected stable-core file, $3 = actual file,
# $4.. = allowed flaky variant lines (exact whole lines).
# Passes iff actual == stable core + a subset of the allowed variants
# (each at most once, order of the stable lines preserved), compared
# BYTE-exact (line terminators included: CRLF or a missing final LF
# fails); anything else — a missing stable line, an unexpected line,
# a flaky id in an undemonstrated form — fails loudly with a diff.
check_stable_core() {
  label="$1"; exp="$2"; act="$3"; shift 3
  python3 - "$label" "$exp" "$act" "$@" <<'PY' || fail "$label differs outside the classified flaky set"
import difflib, sys
label, exp, act, allowed = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
raw_exp = open(exp, "rb").read()
raw_act = open(act, "rb").read()
try:
    want = raw_exp.decode("utf-8").splitlines()
    got = raw_act.decode("utf-8").splitlines()
except UnicodeDecodeError as e:
    print("%s: non-UTF8 bytes: %s" % (label, e))
    sys.exit(1)
allowed_set = set(allowed)
flaky = [l for l in got if l in allowed_set]
stable = [l for l in got if l not in allowed_set]
if len(set(flaky)) != len(flaky):
    print("%s: duplicate flaky line" % label)
    sys.exit(1)
if stable != want:
    print("%s: stable core differs:" % label)
    for l in difflib.unified_diff(want, stable, "expected-stable",
                                  "actual-minus-flaky", lineterm=""):
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
print("%s: stable core holds (%d lines, byte-exact) + %d classified flaky%s" % (
    label, len(want), len(flaky),
    (": " + ", ".join(sorted(set(flaky)))) if flaky else " (none this run)"))
PY
}

# ---------------------------------------------------------------------------
# 1. Build image, assert tag/digest shape.
# ---------------------------------------------------------------------------
note "build image $TAG"
BUILD_CMD="docker build -f docker/Dockerfile.demo -t $TAG ."
echo "build command: $BUILD_CMD"
docker build -f docker/Dockerfile.demo -t "$TAG" . > "$OUT/build.log" 2>&1 \
  || fail "image build failed (see $OUT/build.log)"
tail -3 "$OUT/build.log"

IMGID=$(docker inspect --format '{{.Id}}' "$TAG" 2>/dev/null) \
  || fail "cannot inspect $TAG"
echo "$IMGID" | grep -qE '^sha256:[0-9a-f]{64}$' \
  || fail "image id has unexpected shape: $IMGID"
IMGSIZE=$(docker inspect --format '{{.Size}}' "$TAG")
echo "image id: $IMGID"
echo "image size: $IMGSIZE bytes"
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

# Full lanes exit 1 with exact finding sets (provisional R3 measurement;
# R4 triages each id). Direct is byte-exact (deterministic across 5 runs).
# Proxy asserts a stable 45-line core + 2 classified timing-flaky ids
# (R3d, report section 9.8); any other line fails loudly.
run_check direct full 1
RUN_DIR=$(latest_run "check-direct-full")
cat > "$OUT/exp-full-direct.txt" <<'EOF'
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
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single
failed test_sign_recover.py::TestSignRecoverRecipes::test_sign_recover_single_returns_signature
failed test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_invalid_signature
failed test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_round_trip
EOF
[ "$(wc -l < "$OUT/exp-full-direct.txt")" -eq 32 ] || fail "driver: want 32 expected direct findings"
if ! diff -u "$OUT/exp-full-direct.txt" "$RUN_DIR/findings.txt"; then
  fail "check direct/full findings differ from the exact expected 32"
fi
echo "check direct/full: exact 32 findings match"

run_check proxy full 1
RUN_DIR=$(latest_run "check-proxy-full")
cat > "$OUT/exp-full-proxy.txt" <<'EOF'
crashed test_authenticated_wrap.py::TestAuthenticatedWrap::test_aes_gcm_authenticated_wrap_generated_iv_and_tag
failed ckr/test_ckr_object.py::TestCreateObjectErrors::test_allowed_mechanisms_null_pointer_nonzero_length
failed security/test_ffi_length_boundary.py::TestEddsaNullContext::test_eddsa_null_context_data
failed security/test_ffi_length_boundary.py::TestHkdfNullInfo::test_hkdf_null_info
failed security/test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_hkdf_null_salt
failed security/test_ffi_length_boundary.py::TestSimpleKdfNullData::test_concat_base_data_null
failed test_access.py::TestLoginStates::test_public_session_no_private_keys
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[HOTP]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[HOTP]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC]
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-input]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-length]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-input]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-length]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-input]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-length]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-input]
failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-length]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_CAST128_CBC]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_CAST3_CBC]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_CAST_CBC]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_DES_CBC]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_SHA1_CAST128_CBC]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_SHA1_RC2_128_CBC]
failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_SHA1_RC2_40_CBC]
failed test_pbe.py::TestPBESHA1DES2::test_generate_key_writes_init_vector
failed test_pbe.py::TestPBESHA1DES3::test_generate_key_writes_init_vector
failed test_sign_recover.py::TestSignRecoverRecipes::test_sign_recover_single_returns_signature
failed test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_invalid_signature
failed test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_round_trip
failed test_tls12.py::TestTLS10PreMasterKeyGen::test_tls_key_and_mac_derive
failed test_tls12.py::TestTLS12KeyAndMacDerive::test_key_and_mac_derive
failed test_tls12.py::TestTLS12KeyAndMacDerive::test_key_safe_derive
failed test_tls12.py::TestTLS12KeyAndMacDerive::test_key_safe_derive_ignores_iv_size_request
EOF
[ "$(wc -l < "$OUT/exp-full-proxy.txt")" -eq 45 ] || fail "driver: want 45 stable-core proxy findings"
check_stable_core "check proxy/full findings" "$OUT/exp-full-proxy.txt" \
  "$RUN_DIR/findings.txt" \
  "failed test_ro_session.py::TestROSessionOperations::test_verify_in_ro_session" \
  "failed test_session_state_machine.py::TestLoginStateTransitions::test_open_session_is_public"

# ---------------------------------------------------------------------------
# 4. compare: exit 1 with a stable-core diff + exact shared set.
# The diff asserts a stable 235-line core + 4 classified timing-flaky
# lines (R3d, report section 9.8); the shared set stays byte-exact.
# ---------------------------------------------------------------------------
note "compare (expect exit 1 with exact diff)"
timeout -s KILL "$STEP_TIMEOUT" docker run --rm --network none -v "$OUT:/out" "$TAG" \
  compare > "$OUT/compare.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "compare exited $rc, want 1"
RUN_DIR=$(latest_run compare)
[ -n "$RUN_DIR" ] && [ -f "$RUN_DIR/report.json" ] \
  || fail "compare report.json missing"
cat > "$OUT/exp-diff.txt" <<'EOF'
skipped passed ckr/test_ckr_digest.py::TestDigestInitErrors::test_mechanism_param_invalid
passed failed ckr/test_ckr_object.py::TestCreateObjectErrors::test_allowed_mechanisms_null_pointer_nonzero_length
skipped passed ckr/test_ckr_sign.py::TestSignInitErrors::test_mechanism_param_invalid
passed skipped security/test_arithmetic_overflow.py::TestGcmDecryptUpdateAccumulation::test_gcm_decrypt_update_accumulation_does_not_crash
passed failed security/test_ffi_length_boundary.py::TestEddsaNullContext::test_eddsa_null_context_data
passed failed security/test_ffi_length_boundary.py::TestHkdfNullInfo::test_hkdf_null_info
passed failed security/test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_hkdf_null_salt
passed skipped security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_sign_message_isize_input_len[isize_max]
passed skipped security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_sign_message_isize_input_len[isize_max_plus_1]
passed skipped security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_verify_message_isize_input_len[data_len-isize_max]
passed skipped security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_verify_message_isize_input_len[data_len-isize_max_plus_1]
passed skipped security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_verify_message_isize_input_len[signature_len-isize_max]
passed skipped security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_verify_message_isize_input_len[signature_len-isize_max_plus_1]
passed failed security/test_ffi_length_boundary.py::TestSimpleKdfNullData::test_concat_base_data_null
passed skipped security/test_field_size_boundary.py::TestGenerateKeyValueLenTruncation::test_aes_keygen_value_len_truncation
passed skipped security/test_field_size_boundary.py::TestRsaModulusBitsOversizedValue::test_rsa_modulus_bits_oversized_value
passed skipped security/test_scalar_attr_length_extended.py::TestRsaPrivatePartOversize::test_rsa_private_part_wild_oversized_in_create[exponent-1]
passed skipped security/test_scalar_attr_length_extended.py::TestRsaPrivatePartOversize::test_rsa_private_part_wild_oversized_in_create[prime-1]
passed skipped security/test_scalar_attr_length_extended.py::TestRsaPrivatePartOversize::test_rsa_private_part_wild_oversized_in_create[prime-2]
passed skipped security/test_scalar_attr_length_extended.py::TestRsaPublicKeyAttrOverlong::test_rsa_pub_attr_wild_oversized_in_create[modulus]
passed skipped security/test_scalar_attr_length_extended.py::TestRsaPublicKeyAttrOverlong::test_rsa_pub_attr_wild_oversized_in_create[public-exponent]
passed skipped security/test_scalar_attr_length_extended.py::TestWildOversizedAttrInCreate::test_wild_oversized_bool_attr
passed skipped security/test_scalar_attr_length_extended.py::TestWildOversizedAttrInCreate::test_wild_oversized_ulong_attr
passed failed test_access.py::TestLoginStates::test_public_session_no_private_keys
skipped crashed test_authenticated_wrap.py::TestAuthenticatedWrap::test_aes_gcm_authenticated_wrap_generated_iv_and_tag
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[maximum-BLAKE2B-160]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[maximum-BLAKE2B-256]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[maximum-BLAKE2B-384]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[maximum-BLAKE2B-512]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[minimum-BLAKE2B-160]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[minimum-BLAKE2B-256]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[minimum-BLAKE2B-384]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_boundary_lengths[minimum-BLAKE2B-512]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_tampered_mac[BLAKE2B-160]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_tampered_mac[BLAKE2B-256]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_tampered_mac[BLAKE2B-384]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_tampered_mac[BLAKE2B-512]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_wrong_length_mac[BLAKE2B-160]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_wrong_length_mac[BLAKE2B-256]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_wrong_length_mac[BLAKE2B-384]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_rejects_wrong_length_mac[BLAKE2B-512]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_truncates[BLAKE2B-160]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_truncates[BLAKE2B-256]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_truncates[BLAKE2B-384]
passed skipped test_blake2.py::TestBlake2bKeyed::test_blake2b_hmac_general_truncates[BLAKE2B-512]
passed skipped test_blowfish.py::TestBlowfishEncryption::test_blowfish_cbc_different_ivs
passed skipped test_blowfish.py::TestBlowfishEncryption::test_blowfish_cbc_pad_different_keys
passed skipped test_blowfish.py::TestBlowfishEncryption::test_blowfish_cbc_pad_roundtrip
passed skipped test_blowfish.py::TestBlowfishEncryption::test_blowfish_cbc_roundtrip
passed skipped test_des.py::TestDESEncryption::test_des_cfb64_roundtrip
passed skipped test_des.py::TestDESEncryption::test_des_cfb8_roundtrip
passed skipped test_des.py::TestDESEncryption::test_des_ofb64_roundtrip
passed skipped test_ike.py::TestIKE1ExtendedDerive::test_derive_aes128
passed skipped test_ike.py::TestIKE1ExtendedDerive::test_derive_deterministic
passed skipped test_ike.py::TestIKE1ExtendedDerive::test_derive_skeyid_d
passed skipped test_ike.py::TestIKE1ExtendedDerive::test_different_spis_produce_different_keys
passed skipped test_ike.py::TestIKE1ExtendedDerive::test_extended_hmac_sha256_exact_vector
passed skipped test_ike.py::TestIKE1ExtendedDerive::test_extended_hmac_sha256_multiblock_exact_vector
passed skipped test_ike.py::TestIKE1PRFDerive::test_derive_aes128
passed skipped test_ike.py::TestIKE1PRFDerive::test_derive_deterministic
passed skipped test_ike.py::TestIKE1PRFDerive::test_derive_skeyid
passed skipped test_ike.py::TestIKE1PRFDerive::test_different_nonces_produce_different_keys
passed skipped test_ike.py::TestIKE1PRFDerive::test_prf_hmac_sha256_exact_vector
passed skipped test_mech_derive.py::TestMechDerive::test_derive_produces_key[ARIA_ECB_ENCRYPT_DATA]
passed skipped test_mech_derive.py::TestMechDerive::test_derive_produces_key[CAMELLIA_ECB_ENCRYPT_DATA]
passed skipped test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[BLOWFISH_CBC]
passed skipped test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[BLOWFISH_CBC_PAD]
passed skipped test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[RC2_ECB]
passed skipped test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[BLOWFISH_CBC]
passed skipped test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[BLOWFISH_CBC_PAD]
passed skipped test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[DES_CFB64]
passed skipped test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[DES_CFB8]
passed skipped test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[DES_OFB64]
passed skipped test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[RC2_ECB]
failed skipped test_mech_message.py::TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback
failed skipped test_mech_message.py::TestMessageEncrypt::test_message_encrypt_decrypt_aes_gcm
failed skipped test_mech_message.py::TestMessageEncrypt::test_message_encrypt_multipart_aes_gcm
passed skipped test_mech_message.py::TestMessageEncrypt::test_message_sign_aes_gmac
failed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[AES_GCM]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[BLOWFISH_CBC]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[BLOWFISH_CBC_PAD]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[DES_CFB64]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[DES_CFB8]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[DES_OFB64]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_decrypt_init[RC2_ECB]
failed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[AES_GCM]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[BLOWFISH_CBC]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[BLOWFISH_CBC_PAD]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[DES_CFB64]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[DES_CFB8]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[DES_OFB64]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_encrypt_init[RC2_ECB]
failed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[AES_GMAC]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[BLAKE2B_512_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[AES_GMAC]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[BLOWFISH_CBC]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[BLOWFISH_CBC_PAD]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[DES_CFB64]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[DES_CFB8]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[DES_OFB64]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[RC2_ECB]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[BLOWFISH_CBC]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[BLOWFISH_CBC_PAD]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[DES_CFB64]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[DES_CFB8]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[DES_OFB64]
passed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[RC2_ECB]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
failed skipped test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[BLOWFISH_CBC]
passed skipped test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[BLOWFISH_CBC_PAD]
passed skipped test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_CFB64]
passed skipped test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_CFB8]
passed skipped test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_OFB64]
passed skipped test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[AES_GMAC]
passed skipped test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_streaming_equals_single[AES_GMAC]
passed skipped test_mech_multipart.py::TestMultipartSign::test_streaming_equals_single[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_streaming_equals_single[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_streaming_equals_single[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_multipart.py::TestMultipartSign::test_streaming_equals_single[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_decrypt_without_flag[BLOWFISH_CBC]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_decrypt_without_flag[BLOWFISH_CBC_PAD]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_decrypt_without_flag[DES_CFB64]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_decrypt_without_flag[DES_CFB8]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_decrypt_without_flag[DES_OFB64]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_decrypt_without_flag[RC2_ECB]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[BLOWFISH_CBC]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[BLOWFISH_CBC_PAD]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES_CFB64]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES_CFB8]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES_OFB64]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[RC2_ECB]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_GMAC]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_verify_without_flag[AES_GMAC]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_verify_without_flag[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_verify_without_flag[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_verify_without_flag[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestMissingPermission::test_registry_verify_without_flag[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[BLOWFISH_CBC]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[BLOWFISH_CBC_PAD]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[DES_CFB64]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[DES_CFB8]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[DES_OFB64]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[RC2_ECB]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[BLOWFISH_CBC]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[BLOWFISH_CBC_PAD]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[DES_CFB64]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[DES_CFB8]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[DES_OFB64]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[RC2_ECB]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_GMAC]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[AES_GMAC]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[AES_GMAC]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[AES_GMAC]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[BLAKE2B_160_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[BLAKE2B_256_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[BLAKE2B_384_HMAC_GENERAL]
passed skipped test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[BLAKE2B_512_HMAC_GENERAL]
passed skipped test_operation_termination.py::test_c_encrypt_terminates_after_multipart[BLOWFISH_CBC]
passed skipped test_operation_termination.py::test_c_encrypt_terminates_after_multipart[BLOWFISH_CBC_PAD]
passed skipped test_operation_termination.py::test_c_encrypt_terminates_after_multipart[DES_CFB64]
passed skipped test_operation_termination.py::test_c_encrypt_terminates_after_multipart[DES_CFB8]
passed skipped test_operation_termination.py::test_c_encrypt_terminates_after_multipart[DES_OFB64]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-input]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-length]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-input]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-length]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-input]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-length]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-input]
passed failed test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-length]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_CAST128_CBC]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_CAST3_CBC]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_CAST_CBC]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_MD5_DES_CBC]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_SHA1_CAST128_CBC]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_SHA1_RC2_128_CBC]
passed failed test_pbe.py::TestLegacyPBEVariants::test_generate_key[CKM_PBE_SHA1_RC2_40_CBC]
passed failed test_pbe.py::TestPBESHA1DES2::test_generate_key_writes_init_vector
passed failed test_pbe.py::TestPBESHA1DES3::test_generate_key_writes_init_vector
passed skipped test_ssl3.py::TestSSL3KeyAndMacDerive::test_derive_key_material
passed skipped test_ssl3.py::TestSSL3KeyAndMacDerive::test_derive_key_material_exact_vector
passed skipped test_ssl3.py::TestSSL3KeyAndMacDerive::test_rejects_template_protection_conflict
passed skipped test_ssl3.py::TestSSL3Mac::test_md5_mac_deterministic
passed skipped test_ssl3.py::TestSSL3Mac::test_md5_mac_different_data
passed skipped test_ssl3.py::TestSSL3Mac::test_md5_mac_key_affects_output
passed skipped test_ssl3.py::TestSSL3Mac::test_md5_mac_sign
passed skipped test_ssl3.py::TestSSL3Mac::test_sha1_mac_deterministic
passed skipped test_ssl3.py::TestSSL3Mac::test_sha1_mac_different_data
passed skipped test_ssl3.py::TestSSL3Mac::test_sha1_mac_key_affects_output
passed skipped test_ssl3.py::TestSSL3Mac::test_sha1_mac_sign
passed failed test_tls12.py::TestTLS10PreMasterKeyGen::test_tls_key_and_mac_derive
passed skipped test_tls12.py::TestTLS10PreMasterKeyGen::test_tls_key_and_mac_rejects_template_protection_conflict
passed skipped test_tls12.py::TestTLS10PreMasterKeyGen::test_tls_master_key_derive
passed failed test_tls12.py::TestTLS12KeyAndMacDerive::test_key_and_mac_derive
passed skipped test_tls12.py::TestTLS12KeyAndMacDerive::test_key_and_mac_rejects_template_protection_conflict
passed failed test_tls12.py::TestTLS12KeyAndMacDerive::test_key_safe_derive
passed failed test_tls12.py::TestTLS12KeyAndMacDerive::test_key_safe_derive_ignores_iv_size_request
passed skipped test_tls12.py::TestTLS12KeyAndMacDerive::test_key_safe_rejects_template_protection_conflict
passed skipped test_wtls.py::TestWTLSPreMasterKeyGen::test_generate_pre_master_key
passed skipped test_wtls.py::TestWTLSPreMasterKeyGen::test_generate_yields_non_zero_material
passed skipped test_wtls.py::TestWTLSPreMasterKeyGen::test_two_generated_keys_differ
EOF
cat > "$OUT/exp-shared.txt" <<'EOF'
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_sign_init[HOTP]
failed test_mech_message.py::TestRegistryMessageInit::test_registry_message_verify_init[HOTP]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_sign_wrong_key_type[BLAKE2B_512_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_160_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_256_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_384_HMAC]
failed test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_verify_wrong_key_type[BLAKE2B_512_HMAC]
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_multipart
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_decrypt_single
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_decrypt_roundtrip
failed test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single
failed test_sign_recover.py::TestSignRecoverRecipes::test_sign_recover_single_returns_signature
failed test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_invalid_signature
failed test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_round_trip
EOF
[ "$(wc -l < "$OUT/exp-diff.txt")" -eq 235 ] || fail "driver: want 235 stable-core diff lines"
check_stable_core "compare diff" "$OUT/exp-diff.txt" "$RUN_DIR/diff.txt" \
  "passed skipped test_object.py::TestSessionObjects::test_multiple_keys_same_type" \
  "passed failed test_ro_session.py::TestROSessionOperations::test_verify_in_ro_session" \
  "passed skipped test_search.py::TestObjectSearch::test_find_many_objects" \
  "passed failed test_session_state_machine.py::TestLoginStateTransitions::test_open_session_is_public"
if ! diff -u "$OUT/exp-shared.txt" "$RUN_DIR/shared-findings.txt"; then
  fail "compare shared set differs from the exact expected set"
fi
echo "compare: stable-core diff + exact shared set match"

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
grep -q 'PROVISIONAL' "$OUT/help-check.log" || fail "check help marker missing"
grep -q 'PROVISIONAL' "$OUT/help-compare.log" || fail "compare help marker missing"
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
echo "examples: check-smoke x2 + uri-demo hold"

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
in the proxy stage), pkcs11-check == 0.2.2 (venv + version assertion),
and every entrypoint verdict asserted byte-exact on its stable core by
this driver. Four proxy-lane timing-flaky test ids are classified with
enumerated variant forms (report section 9.8); any line outside the
stable core + classified variants fails the driver loudly.
Functional reproducibility = same versions + same outcomes above.
EOF
cat "$OUT/reproducibility-note.txt"

echo "PASS: test-demo-image.sh (demo + check x4 + compare + help/matrix/examples/json + UID + nonet + floor)"
