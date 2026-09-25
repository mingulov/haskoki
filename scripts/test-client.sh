#!/bin/sh
# scripts/test-client.sh -- test-only Haskell client driver proof.
#
# Builds everything, locates the shared module and the haskoki-client
# CLI, and drives the C ABI end to end through the in-repo Haskell
# client (a genuine foreign client, independent of the C consumers):
#   slots     library + slot/token discovery
#   mechs     mechanism list is non-empty (109 served rows)
#   digest    SHA-256 of a fixture agrees with sha256sum, and
#             single-part agrees with multipart (checked in-CLI)
#   rand      16 bytes out for 16 bytes asked
#   roundtrip AES-CBC-PAD + RFC 4231 HMAC + ECDSA P-256 + SHA256-KDF
#
# Usage:
#   scripts/test-client.sh
#
# Exit status: 0 iff every client proof passes.
set -u

HERE=$(dirname "$0")
PKG="$HERE/.."
cd "$PKG" || exit 1

fail() {
  echo "FAIL: $1"
  exit 1
}

cabal build all || fail "cabal build all failed"

# 1. Locate exactly one built shared module.
SO_LIST=$(find dist-newstyle -name 'libhaskoki*.so' 2>/dev/null | sort)
SO_COUNT=$(echo "$SO_LIST" | grep -c . || true)
[ -n "$SO_LIST" ] || fail "no loadable module found (run: cabal build all)"
[ "$SO_COUNT" -eq 1 ] || fail "expected exactly one libhaskoki*.so, found $SO_COUNT"
SO="$SO_LIST"
echo "module under test: $SO"

# 2. Locate the client CLI.
CLI=$(find dist-newstyle -path '*haskoki-client/haskoki-client' -type f 2>/dev/null | sort | head -1)
[ -n "$CLI" ] || fail "haskoki-client binary not found (run: cabal build all)"
echo "client under test: $CLI"

# 3. Discovery.
SLOTS_OUT=$("$CLI" "$SO" slots) || fail "slots refused"
echo "$SLOTS_OUT"
echo "$SLOTS_OUT" | grep -q "slots: 1" || fail "expected exactly one slot"
echo "$SLOTS_OUT" | grep -q 'label="haskoki-demo"' || fail "demo token label missing"

MECHS_OUT=$("$CLI" "$SO" mechs) || fail "mechs refused"
echo "$MECHS_OUT" | head -2
echo "$MECHS_OUT" | grep -q "mechanisms on slot 0: 109" || fail "expected 109 served mechanisms"

# 4. Digest agrees with the system sha256sum (multipart agreement is
# asserted inside the CLI itself).
printf 'client digest fixture\n' > /tmp/haskoki-client-fixture.txt
DIGEST_OUT=$("$CLI" "$SO" digest /tmp/haskoki-client-fixture.txt) || fail "digest refused"
echo "$DIGEST_OUT"
EXPECT=$(sha256sum /tmp/haskoki-client-fixture.txt | awk '{print $1}')
echo "$DIGEST_OUT" | grep -q "$EXPECT" || fail "client digest disagrees with sha256sum"

# 5. Random: 16 bytes out.
RAND_OUT=$("$CLI" "$SO" rand 16) || fail "rand refused"
[ "${#RAND_OUT}" -eq 32 ] || fail "rand 16 did not yield 16 bytes hex (got: $RAND_OUT)"
echo "rand 16 -> 16 bytes OK"

# 6. Crypto roundtrips (vectors + negative legs asserted in-CLI).
ROUND_OUT=$("$CLI" "$SO" roundtrip) || fail "roundtrip refused"
echo "$ROUND_OUT"
echo "$ROUND_OUT" | grep -q "AES-CBC-PAD roundtrip OK" || fail "AES roundtrip line missing"
echo "$ROUND_OUT" | grep -q "HMAC-SHA256(RFC4231#1) = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 OK" \
  || fail "HMAC RFC 4231 vector mismatch"
echo "$ROUND_OUT" | grep -q "ECDSA P-256 sign/verify OK" || fail "EC roundtrip line missing"
echo "$ROUND_OUT" | grep -q "SHA256-KDF derive OK (16 bytes)" || fail "KDF line missing"

# 7. Negative legs are asserted inside the CLI (verify-after-destroy
# refuses, corrupt ECDSA signature refuses); reaching this line means
# they held.

echo "PASS: test-client.sh (Haskell client driver proof)"
