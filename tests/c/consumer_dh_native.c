/* tests/c/consumer_dh_native.c — C1 (G01): native DH peer bytes survive
 * normalization through public C_DeriveKey.
 *
 * The PKCS#11 parameter form for CKM_DH_PKCS_DERIVE is the bare
 * big-endian peer value (no struct). The provider must wrap those bytes
 * whole into its internal (kdf, len, peer) frame; it must never mistake
 * a frame-shaped peer for an already-internal frame (the old intake
 * passed such images through, silently dropping the peer's leading
 * bytes — e.g. deriving peer 2 for a full-width ffdhe2048 value).
 *
 * Pins (public surface, no provider internals):
 *   - the report's full-width ffdhe2048 peer (8 zero bytes, BE64(240),
 *     239 zero bytes, 0x02) derives exactly the independent oracle's
 *     y^x mod p for that complete integer (pinned x and domain);
 *   - the same derivation differs from the peer-2 derivation (the old
 *     code produced the peer-2 secret here);
 *   - equivalent leading-zero encodings (256-byte full form vs the
 *     241-byte minimal form of the same integer) agree;
 *   - PKCS#11 truncation drops leading bytes (CKA_VALUE_LEN=32 keeps
 *     the last 32 oracle bytes);
 *   - invalid peers (y=1, y=p, empty) refuse with exactly
 *     CKR_MECHANISM_PARAM_INVALID and write no handle;
 *   - output reads carry canary guards proving no over/under-write.
 *
 * The oracle is a hand-rolled 2048-bit modular exponentiation in this
 * TU (schoolbook multiply, shift-subtract reduction, square-and-
 * multiply) — independent of both the provider and OpenSSL. Every
 * setup call, mechanism call, and result (exact rv, hex images) is
 * printed, so a refusal caused by setup cannot masquerade as a passing
 * negative control.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_dh_native <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("FAIL [%s:%d]: ", __FILE__, __LINE__);                        \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    }                                                                      \
  } while (0)

static void hex_of(const CK_BYTE *b, CK_ULONG n, char *out) {
  static const char *d = "0123456789abcdef";
  CK_ULONG i;
  for (i = 0; i < n; i++) {
    out[2 * i] = d[(b[i] >> 4) & 0xf];
    out[2 * i + 1] = d[b[i] & 0xf];
  }
  out[2 * n] = '\0';
}

/* ---- minimal big-integer oracle (independent of the provider) ----
 * Unsigned little-endian 32-bit limbs, fixed 2048-bit width. Only the
 * operations needed for one y^x mod p. All buffers are caller-sized;
 * every index is bounded by BN_LIMBS/BN_WIDE below. */

#define BN_LIMBS 64u /* 2048 bits */
#define BN_WIDE (2u * BN_LIMBS)

static void bn_zero(uint32_t *a, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    a[i] = 0u;
  }
}

/* Big-endian bytes into limbs. Precondition: n <= nl * 4. */
static void bn_from_be(const CK_BYTE *be, size_t n, uint32_t *a, size_t nl) {
  size_t i;
  bn_zero(a, nl);
  for (i = 0; i < n; i++) {
    size_t bit = (n - 1u - i) * 8u;
    a[bit / 32u] |= (uint32_t)be[i] << (bit % 32u);
  }
}

/* Limbs into big-endian bytes, zero-padded on the left. */
static void bn_to_be(const uint32_t *a, size_t nl, CK_BYTE *be, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    size_t bit = (n - 1u - i) * 8u;
    CK_BYTE v = 0;
    if (bit / 32u < nl) {
      v = (CK_BYTE)((a[bit / 32u] >> (bit % 32u)) & 0xffu);
    }
    be[i] = v;
  }
}

static size_t bn_bits(const uint32_t *a, size_t n) {
  size_t i = n;
  while (i > 0u) {
    uint32_t w;
    size_t b;
    i--;
    w = a[i];
    if (w == 0u) {
      continue;
    }
    b = 32u;
    while ((w >> (b - 1u)) == 0u) {
      b--;
    }
    return i * 32u + b;
  }
  return 0u;
}

static int bn_cmp(const uint32_t *a, const uint32_t *b, size_t n) {
  size_t i = n;
  while (i > 0u) {
    i--;
    if (a[i] != b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
}

/* a -= b. Precondition: a >= b (returns the final borrow: 0 then). */
static uint32_t bn_sub(uint32_t *a, const uint32_t *b, size_t n) {
  uint64_t borrow = 0u;
  size_t i;
  for (i = 0; i < n; i++) {
    uint64_t ai = (uint64_t)a[i];
    uint64_t bi = (uint64_t)b[i] + borrow;
    a[i] = (uint32_t)(ai - bi);
    borrow = (ai < bi) ? 1u : 0u;
  }
  return (uint32_t)borrow;
}

/* out = a << shift, truncated to n limbs. */
static void bn_shl(const uint32_t *a, size_t n, size_t shift, uint32_t *out) {
  size_t ws = shift / 32u;
  size_t bs = shift % 32u;
  size_t i;
  bn_zero(out, n);
  for (i = ws; i < n; i++) {
    uint64_t v = (uint64_t)a[i - ws] << bs;
    if (bs != 0u && i - ws > 0u) {
      v |= (uint64_t)a[i - ws - 1u] >> (32u - bs);
    }
    out[i] = (uint32_t)v;
  }
}

/* c(2n) = a(n) * b(n), schoolbook. */
static void bn_mul(const uint32_t *a, const uint32_t *b, uint32_t *c, size_t n) {
  size_t i, j;
  bn_zero(c, 2u * n);
  for (i = 0; i < n; i++) {
    uint64_t carry = 0u;
    for (j = 0; j < n; j++) {
      uint64_t v =
          (uint64_t)c[i + j] + (uint64_t)a[i] * (uint64_t)b[j] + carry;
      c[i + j] = (uint32_t)v;
      carry = v >> 32u;
    }
    c[i + n] = (uint32_t)((uint64_t)c[i + n] + carry);
  }
}

/* r(n) = c(2n) mod p(n); c is consumed. Precondition: p != 0. */
static void bn_mod(uint32_t *c, const uint32_t *p, uint32_t *r, size_t n) {
  uint32_t pp[BN_WIDE];
  uint32_t t[BN_WIDE];
  size_t k, pb;
  bn_zero(pp, 2u * n);
  for (k = 0; k < n; k++) {
    pp[k] = p[k];
  }
  pb = bn_bits(pp, 2u * n);
  while (bn_cmp(c, pp, 2u * n) >= 0) {
    size_t sh = bn_bits(c, 2u * n) - pb;
    bn_shl(pp, 2u * n, sh, t);
    if (bn_cmp(t, c, 2u * n) > 0) {
      sh--;
      bn_shl(pp, 2u * n, sh, t);
    }
    bn_sub(c, t, 2u * n);
  }
  for (k = 0; k < n; k++) {
    r[k] = c[k];
  }
}

/* r(n) = (a(n) * b(n)) mod p(n). */
static void bn_mulmod(const uint32_t *a, const uint32_t *b, const uint32_t *p,
                      uint32_t *r, size_t n) {
  uint32_t c[BN_WIDE];
  bn_mul(a, b, c, n);
  bn_mod(c, p, r, n);
}

static int bn_bit(const uint32_t *a, size_t bit) {
  return (int)((a[bit / 32u] >> (bit % 32u)) & 1u);
}

/* out = base^exp mod prime, big-endian out_len bytes. Returns 1 on
 * success, 0 on a shape violation (never a partial write). */
static int dh_oracle(const CK_BYTE *base, size_t base_len, const CK_BYTE *exp,
                     size_t exp_len, const CK_BYTE *prime, size_t prime_len,
                     CK_BYTE *out, size_t out_len) {
  uint32_t b[BN_LIMBS], e[BN_LIMBS], p[BN_LIMBS], r[BN_LIMBS], t[BN_LIMBS];
  uint32_t bw[BN_WIDE];
  size_t top, bit, k;
  if (base == NULL || exp == NULL || prime == NULL || out == NULL) {
    return 0;
  }
  if (base_len == 0u || base_len > 256u || exp_len == 0u || exp_len > 256u ||
      prime_len != 256u || out_len != 256u) {
    return 0;
  }
  bn_from_be(base, base_len, b, BN_LIMBS);
  bn_from_be(exp, exp_len, e, BN_LIMBS);
  bn_from_be(prime, prime_len, p, BN_LIMBS);
  if (bn_bits(p, BN_LIMBS) == 0u) {
    return 0;
  }
  /* Reduce the base first: full-width peers are the norm here. */
  bn_zero(bw, BN_WIDE);
  for (k = 0; k < BN_LIMBS; k++) {
    bw[k] = b[k];
  }
  bn_mod(bw, p, t, BN_LIMBS);
  for (k = 0; k < BN_LIMBS; k++) {
    b[k] = t[k];
  }
  bn_zero(r, BN_LIMBS);
  r[0] = 1u;
  top = bn_bits(e, BN_LIMBS);
  for (bit = top; bit > 0u; bit--) {
    bn_mulmod(r, r, p, t, BN_LIMBS);
    for (k = 0; k < BN_LIMBS; k++) {
      r[k] = t[k];
    }
    if (bn_bit(e, bit - 1u) != 0) {
      bn_mulmod(r, b, p, t, BN_LIMBS);
      for (k = 0; k < BN_LIMBS; k++) {
        r[k] = t[k];
      }
    }
  }
  bn_to_be(r, BN_LIMBS, out, out_len);
  return 1;
}

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

/* ---- pinned domain: ffdhe2048 (RFC 7919 §A.1), g = 2 ---- */
static const CK_BYTE P_FFDHE2048[256] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58, 0xa2, 0xbb, 0x4a, 0x9a,
  0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1, 0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95,
  0xa9, 0xe1, 0x36, 0x41, 0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
  0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02, 0xae, 0xc4, 0x61, 0x7a,
  0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61, 0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0,
  0x85, 0x63, 0x65, 0x55, 0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
  0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda, 0xf3, 0xef, 0xe8, 0x72,
  0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35, 0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a,
  0xbc, 0x0a, 0xb1, 0x82, 0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
  0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3, 0xde, 0x39, 0x4d, 0xf4,
  0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19, 0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70,
  0x9e, 0x02, 0xfc, 0xe1, 0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
  0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32, 0xee, 0xf2, 0x81, 0x83,
  0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73, 0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05,
  0xc5, 0x8e, 0xf1, 0x83, 0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
  0x88, 0x6b, 0x42, 0x38, 0x61, 0x28, 0x5c, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static CK_BYTE G_DH[1] = { 0x02 };

/* Pinned private value x: bytes 0x01..0x20 (1 < x < p - 1). */
static CK_BYTE X_PRIV[32] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* The report's full-width peer: 8 zero bytes, BE64(240), 239 zero
 * bytes, 0x02 (256 bytes total, the integer 240 * 2^1920 + 2). Under
 * the old intake this parsed as the internal (kdf=0, len=240, peer)
 * frame and derived the peer-2 secret. */
static void build_full_peer(CK_BYTE *peer) {
  memset(peer, 0, 256);
  peer[15] = 0xF0;
  peer[255] = 0x02;
}

#define GUARD 16u
#define CANARY 0xA5u

/* Derive one generic-secret object; *ph is zeroed first so a refusal
 * provably writes no handle. */
static CK_RV derive_one(CK_SESSION_HANDLE s, void *peer, CK_ULONG peer_len,
                        CK_ULONG vlen, CK_OBJECT_HANDLE base,
                        CK_OBJECT_HANDLE *ph) {
  CK_OBJECT_CLASS dcls = CKO_SECRET_KEY;
  CK_KEY_TYPE dkt = CKK_GENERIC_SECRET;
  CK_ATTRIBUTE dt[] = {
    { CKA_CLASS, &dcls, sizeof(dcls) },
    { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
  };
  CK_MECHANISM m;
  m.mechanism = CKM_DH_PKCS_DERIVE;
  m.pParameter = peer;
  m.ulParameterLen = peer_len;
  *ph = 0;
  return f->C_DeriveKey(s, &m, base, dt, 6, ph);
}

/* Read exactly want bytes of CKA_VALUE into out through a canary-
 * guarded buffer; verifies the guards and the reported length. */
static CK_RV read_guarded(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                          CK_BYTE *out, CK_ULONG want) {
  CK_BYTE buf[256 + 2u * GUARD];
  CK_ATTRIBUTE g[] = { { CKA_VALUE, buf + GUARD, want } };
  CK_ULONG i;
  CK_RV rv;
  if (want == 0u || want > 256u) {
    CHECK(0, "read_guarded: bad want %lu", (unsigned long)want);
    return CKR_ARGUMENTS_BAD;
  }
  memset(buf, CANARY, sizeof(buf));
  g[0].ulValueLen = want;
  rv = f->C_GetAttributeValue(s, h, g, 1);
  if (rv != CKR_OK) {
    return rv;
  }
  CHECK(g[0].ulValueLen == want, "secret length %lu, want %lu",
        (unsigned long)g[0].ulValueLen, (unsigned long)want);
  for (i = 0; i < GUARD; i++) {
    CHECK(buf[i] == CANARY, "under-write guard clobbered at %lu",
          (unsigned long)i);
  }
  for (i = 0; i < (CK_ULONG)(sizeof(buf)) - GUARD - want; i++) {
    CHECK(buf[GUARD + want + i] == CANARY, "over-write guard clobbered at %lu",
          (unsigned long)i);
  }
  memcpy(out, buf + GUARD, want);
  return CKR_OK;
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_CLASS privCls = CKO_PRIVATE_KEY;
  CK_KEY_TYPE dhKt = CKK_DH;
  CK_OBJECT_HANDLE hpriv = 0, hsec = 0, hbad = 0;
  CK_ATTRIBUTE privT[9];
  CK_BYTE peer_full[256], peer_min[241], peer_two[1], peer_one[1];
  CK_BYTE s_full[256], s_min[256], s_two[256], got[256], got32[32];
  char hx[513], hx2[513];

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  dl = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(dl != NULL, "dlopen %s", argv[1]);
  if (dl == NULL) {
    return 1;
  }
  getList = (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
  CHECK(getList != NULL, "dlsym C_GetFunctionList");
  if (getList == NULL) {
    return 1;
  }
  rv = getList(&f);
  CHECK(rv == CKR_OK && f != NULL, "C_GetFunctionList ok");
  if (rv != CKR_OK || f == NULL) {
    return 1;
  }
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok (rv=0x%lx)", (unsigned long)rv);
  rv = f->C_GetSlotList(CK_FALSE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots >= 1, "slot present (rv=0x%lx)",
        (unsigned long)rv);
  if (rv != CKR_OK || nslots < 1) {
    return 1;
  }
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok (rv=0x%lx)",
        (unsigned long)rv);
  if (rv != CKR_OK || sess == 0) {
    return 1;
  }

  /* ---- fixture shapes ---- */
  build_full_peer(peer_full);
  memcpy(peer_min, peer_full + 15, sizeof(peer_min));
  peer_two[0] = 0x02;
  peer_one[0] = 0x01;
  CHECK(peer_full[0] == 0x00 && peer_full[7] == 0x00, "full peer leading zeros");
  CHECK(peer_full[8] == 0x00 && peer_full[14] == 0x00 && peer_full[15] == 0xF0,
        "full peer BE64(240)");
  CHECK(peer_full[16] == 0x00 && peer_full[254] == 0x00 && peer_full[255] == 0x02,
        "full peer tail");
  CHECK(peer_min[0] == 0xF0 && peer_min[240] == 0x02, "minimal peer shape");
  CHECK(sizeof(peer_full) == 256u && sizeof(peer_min) == 241u, "peer widths");

  /* ---- oracle secrets (independent math) ---- */
  CHECK(dh_oracle(peer_full, sizeof(peer_full), X_PRIV, sizeof(X_PRIV),
                  P_FFDHE2048, sizeof(P_FFDHE2048), s_full, sizeof(s_full)) == 1,
        "oracle full peer");
  CHECK(dh_oracle(peer_min, sizeof(peer_min), X_PRIV, sizeof(X_PRIV),
                  P_FFDHE2048, sizeof(P_FFDHE2048), s_min, sizeof(s_min)) == 1,
        "oracle minimal peer");
  CHECK(dh_oracle(peer_two, sizeof(peer_two), X_PRIV, sizeof(X_PRIV),
                  P_FFDHE2048, sizeof(P_FFDHE2048), s_two, sizeof(s_two)) == 1,
        "oracle peer 2");
  hex_of(s_full, sizeof(s_full), hx);
  hex_of(s_two, sizeof(s_two), hx2);
  printf("oracle: full=%s\n", hx);
  printf("oracle: peer2=%s\n", hx2);
  CHECK(memcmp(s_full, s_min, sizeof(s_full)) == 0,
        "oracle: leading-zero encodings agree");
  CHECK(memcmp(s_full, s_two, sizeof(s_full)) != 0,
        "oracle: full peer differs from peer 2");

  /* ---- pinned private-key import ---- */
  privT[0].type = CKA_CLASS;
  privT[0].pValue = &privCls;
  privT[0].ulValueLen = sizeof(privCls);
  privT[1].type = CKA_KEY_TYPE;
  privT[1].pValue = &dhKt;
  privT[1].ulValueLen = sizeof(dhKt);
  privT[2].type = CKA_PRIME;
  privT[2].pValue = (CK_VOID_PTR)P_FFDHE2048;
  privT[2].ulValueLen = sizeof(P_FFDHE2048);
  privT[3].type = CKA_BASE;
  privT[3].pValue = G_DH;
  privT[3].ulValueLen = sizeof(G_DH);
  privT[4].type = CKA_VALUE;
  privT[4].pValue = X_PRIV;
  privT[4].ulValueLen = sizeof(X_PRIV);
  privT[5].type = CKA_TOKEN;
  privT[5].pValue = &bFalse;
  privT[5].ulValueLen = sizeof(bFalse);
  privT[6].type = CKA_PRIVATE;
  privT[6].pValue = &bFalse;
  privT[6].ulValueLen = sizeof(bFalse);
  privT[7].type = CKA_SENSITIVE;
  privT[7].pValue = &bFalse;
  privT[7].ulValueLen = sizeof(bFalse);
  privT[8].type = CKA_DERIVE;
  privT[8].pValue = &bTrue;
  privT[8].ulValueLen = sizeof(bTrue);
  rv = f->C_CreateObject(sess, privT, 9, &hpriv);
  printf("setup: C_CreateObject(DH priv) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hpriv);
  CHECK(rv == CKR_OK && hpriv != 0, "DH private import");
  if (rv != CKR_OK || hpriv == 0) {
    return 1;
  }

  /* ---- full-width peer derives the full-integer secret ---- */
  rv = derive_one(sess, peer_full, sizeof(peer_full), 256, hpriv, &hsec);
  printf("call: derive(full,256) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hsec);
  CHECK(rv == CKR_OK && hsec != 0, "derive full-width peer");
  if (rv == CKR_OK && hsec != 0) {
    rv = read_guarded(sess, hsec, got, sizeof(got));
    printf("result: derive(full,256) read rv=0x%lx\n", (unsigned long)rv);
    CHECK(rv == CKR_OK, "read full secret");
    if (rv == CKR_OK) {
      hex_of(got, sizeof(got), hx);
      printf("result: secret(full)=%s\n", hx);
      CHECK(memcmp(got, s_full, sizeof(got)) == 0,
            "full peer derives the oracle secret");
      CHECK(memcmp(got, s_two, sizeof(got)) != 0,
            "full peer differs from peer 2 (G01)");
    }
  }

  /* ---- minimal encoding of the same integer agrees ---- */
  rv = derive_one(sess, peer_min, sizeof(peer_min), 256, hpriv, &hsec);
  printf("call: derive(min241,256) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hsec);
  CHECK(rv == CKR_OK && hsec != 0, "derive minimal peer");
  if (rv == CKR_OK && hsec != 0) {
    rv = read_guarded(sess, hsec, got, sizeof(got));
    printf("result: derive(min241,256) read rv=0x%lx\n", (unsigned long)rv);
    CHECK(rv == CKR_OK, "read minimal secret");
    if (rv == CKR_OK) {
      CHECK(memcmp(got, s_full, sizeof(got)) == 0,
            "leading-zero encodings agree");
    }
  }

  /* ---- peer 2 derives its own (different) secret ---- */
  rv = derive_one(sess, peer_two, sizeof(peer_two), 256, hpriv, &hsec);
  printf("call: derive(peer2,256) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hsec);
  CHECK(rv == CKR_OK && hsec != 0, "derive peer 2");
  if (rv == CKR_OK && hsec != 0) {
    rv = read_guarded(sess, hsec, got, sizeof(got));
    printf("result: derive(peer2,256) read rv=0x%lx\n", (unsigned long)rv);
    CHECK(rv == CKR_OK, "read peer-2 secret");
    if (rv == CKR_OK) {
      CHECK(memcmp(got, s_two, sizeof(got)) == 0, "peer 2 matches its oracle");
      CHECK(memcmp(got, s_full, sizeof(got)) != 0, "peer 2 differs from full");
    }
  }

  /* ---- PKCS#11 truncation drops leading bytes ---- */
  rv = derive_one(sess, peer_full, sizeof(peer_full), 32, hpriv, &hsec);
  printf("call: derive(full,32) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hsec);
  CHECK(rv == CKR_OK && hsec != 0, "derive truncated");
  if (rv == CKR_OK && hsec != 0) {
    rv = read_guarded(sess, hsec, got32, sizeof(got32));
    printf("result: derive(full,32) read rv=0x%lx\n", (unsigned long)rv);
    CHECK(rv == CKR_OK, "read truncated secret");
    if (rv == CKR_OK) {
      hex_of(got32, sizeof(got32), hx);
      printf("result: secret(full,32)=%s\n", hx);
      CHECK(memcmp(got32, s_full + 224, sizeof(got32)) == 0,
            "truncation keeps the trailing bytes");
    }
  }

  /* ---- invalid-peer controls (exact refusal, no handle) ---- */
  rv = derive_one(sess, peer_one, sizeof(peer_one), 256, hpriv, &hbad);
  printf("call: derive(y=1) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "y=1 refused typed without a handle");
  rv = derive_one(sess, (CK_VOID_PTR)P_FFDHE2048, sizeof(P_FFDHE2048), 256,
                  hpriv, &hbad);
  printf("call: derive(y=p) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "y=p refused typed without a handle");
  rv = derive_one(sess, NULL_PTR, 0, 256, hpriv, &hbad);
  printf("call: derive(empty) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "empty peer refused typed without a handle");

  /* ---- overlong peers refuse (G01 escape regression) ----
   * A 4097-byte image shaped as BE64(0), BE64(4081), 4080 zeros, 02
   * parses as the internal (kdf=0, peer~=2) frame; the intake must
   * map it recipe-refused instead of passing it through to derive
   * the peer-2 secret. */
  {
    static CK_BYTE esc[4097];
    static CK_BYTE big[4097];
    CK_ULONG i;
    memset(esc, 0, sizeof(esc));
    esc[14] = 15;
    esc[15] = 241;
    esc[4096] = 0x02;
    for (i = 0; i < (CK_ULONG)sizeof(big); i++) {
      big[i] = 0x01;
    }
    CHECK(sizeof(esc) == 4097u, "escape width");
    rv = derive_one(sess, esc, sizeof(esc), 256, hpriv, &hbad);
    printf("call: derive(escape4097) rv=0x%lx h=%lu\n",
           (unsigned long)rv, (unsigned long)hbad);
    CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
          "frame-shaped overlong refused typed without a handle");
    rv = derive_one(sess, big, sizeof(big), 256, hpriv, &hbad);
    printf("call: derive(big4097) rv=0x%lx h=%lu\n",
           (unsigned long)rv, (unsigned long)hbad);
    CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
          "generic overlong refused typed without a handle");
  }

  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok (rv=0x%lx)", (unsigned long)rv);

  if (g_failures != 0) {
    printf("consumer_dh_native: %d FAILURE(S)\n", g_failures);
    return 1;
  }
  printf("consumer_dh_native: PASS\n");
  return 0;
}
