/* tests/c/consumer_x942_derive.c — X9.42 DH derive through public
 * C_DeriveKey with a derive-capable base.
 *
 * The external checker generates X9.42 DH key pairs without
 * CKA_DERIVE=TRUE and then derives, so since the provider default
 * follows PKCS#11 3.2 Table 26 (CKA_DERIVE false on new keys) its
 * X9.42 derive tests fail before reaching parameter validation and
 * its five X9.42 negative tests no longer exercise the provider's
 * parameter refusals. This consumer pins the same behaviors through
 * the C ABI with keys generated carrying CKA_DERIVE=TRUE:
 *
 * Pins (public surface, no provider internals):
 *   - positive: two parties on one domain derive the same AES-128
 *     key (CKD_NULL, empty OtherInfo), a third party's exchange
 *     differs, and the derived key encrypts/decrypts (AES-ECB
 *     round-trip);
 *   - missing peer public value refuses with exactly
 *     CKR_MECHANISM_PARAM_INVALID and writes no handle;
 *   - malformed peer (y = 1, outside 1 < y < p - 1) refuses with
 *     exactly CKR_MECHANISM_PARAM_INVALID and writes no handle;
 *   - CKD_NULL with non-empty OtherInfo refuses with exactly
 *     CKR_MECHANISM_PARAM_INVALID and writes no handle;
 *   - CKD_SHA1_KDF_ASN1 with missing OtherInfo refuses with exactly
 *     CKR_MECHANISM_PARAM_INVALID and writes no handle;
 *   - an invalid KDF selector refuses with exactly
 *     CKR_MECHANISM_PARAM_INVALID and writes no handle.
 *
 * Every setup call, mechanism call, and result (exact rv, hex
 * images) is printed, so a refusal caused by setup cannot
 * masquerade as a passing negative control. Hex images of
 * generated values and derived keys differ on every run, so they
 * carry the "crypto:" prefix (excluded from the proxy parity
 * transcript); the equality checks on them still run here. The negative legs
 * reuse the base that the positive leg proves derive-capable, so
 * each refusal is parameter-caused.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_x942_derive <path-to-libhaskoki.so>
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

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

/* ---- pinned X9.42 domain: the 1024-bit (p, g, q) triple the engine
 * suite mints on (tests/engine/OpenSSLSpec.hs dhX942P/G/Q). ---- */
static const CK_BYTE P_X942[128] = {
  0xdd, 0xc1, 0x7b, 0x05, 0x8e, 0x1e, 0xc1, 0x5b, 0x51, 0x99, 0x6f, 0x85, 0xea, 0xe0, 0xb6, 0x78,
  0xea, 0x9b, 0xb7, 0x24, 0x44, 0x15, 0x9f, 0xe2, 0xfc, 0xd0, 0xf4, 0x4f, 0x7b, 0xe7, 0xe7, 0x37,
  0xee, 0xeb, 0xe9, 0x4c, 0x47, 0xe7, 0x51, 0xbc, 0xd8, 0x26, 0xc5, 0x39, 0x60, 0xd7, 0xe1, 0xaf,
  0x0f, 0x0f, 0x42, 0x1f, 0x4f, 0x31, 0x10, 0x4d, 0x07, 0xb1, 0x3a, 0xf4, 0x01, 0xed, 0x76, 0x56,
  0x7b, 0x31, 0xd2, 0xeb, 0xf1, 0xea, 0xac, 0x37, 0xc6, 0x26, 0x69, 0x8e, 0x60, 0xdf, 0xf1, 0x28,
  0xc6, 0x71, 0xf9, 0x05, 0x56, 0x00, 0x74, 0x05, 0x81, 0x50, 0x8c, 0x10, 0x08, 0x14, 0x44, 0x4f,
  0xfa, 0x21, 0xfa, 0xda, 0x6a, 0xf0, 0x11, 0x26, 0x0c, 0x1b, 0xc0, 0x70, 0xa3, 0xd5, 0x8f, 0x9a,
  0x09, 0x86, 0x07, 0xd9, 0x2a, 0x93, 0x8e, 0xff, 0x5a, 0x16, 0xfd, 0xc3, 0x88, 0xe4, 0x1e, 0x09
};
static const CK_BYTE G_X942[128] = {
  0xd1, 0xa4, 0x42, 0x8b, 0x2e, 0x04, 0x06, 0x05, 0x34, 0xad, 0x2a, 0x28, 0x4a, 0x70, 0x39, 0x27,
  0x6b, 0xf6, 0x30, 0x6a, 0x88, 0xbf, 0xde, 0x2d, 0x92, 0x33, 0x2a, 0x82, 0x4d, 0xa2, 0x17, 0x82,
  0xe3, 0x0b, 0x36, 0x42, 0x62, 0x5f, 0x08, 0xca, 0x00, 0xc5, 0x99, 0x76, 0x26, 0xd6, 0x73, 0x3d,
  0x00, 0xea, 0xfc, 0xc2, 0x06, 0xaf, 0xbb, 0xda, 0xfb, 0x00, 0x86, 0xdd, 0xf1, 0xd0, 0x6d, 0x48,
  0x87, 0xff, 0x77, 0xe5, 0x49, 0x93, 0x7b, 0xdd, 0xe1, 0x81, 0xe6, 0x95, 0x5c, 0xec, 0x0b, 0x29,
  0xe7, 0x10, 0x16, 0x8d, 0x89, 0x16, 0x87, 0x51, 0x5c, 0x1a, 0xd3, 0xe0, 0x3e, 0xee, 0x3f, 0x60,
  0xf9, 0x6a, 0x90, 0x63, 0xd5, 0x40, 0xb7, 0x90, 0x7c, 0xdb, 0x24, 0xb9, 0x9d, 0xfd, 0x49, 0x0e,
  0x3c, 0xc4, 0x47, 0xbe, 0x9d, 0x47, 0xcd, 0xef, 0xde, 0x5a, 0xa3, 0x0c, 0x85, 0x7a, 0x9c, 0xfa
};
static const CK_BYTE Q_X942[28] = {
  0xfc, 0xbd, 0x52, 0x88, 0x1b, 0x3c, 0x39, 0x75, 0xa6, 0x61, 0xce, 0x18, 0xc8, 0x67, 0x83, 0x26,
  0x17, 0xb4, 0x9b, 0x0d, 0xc2, 0xc4, 0x67, 0xc1, 0x0c, 0x26, 0x4a, 0x67
};

#define GUARD 16u
#define CANARY 0xA5u
#define MAX_PUB 256u

/* Generate one X9.42 DH pair on the pinned domain; the private half
 * carries CKA_DERIVE=TRUE (the derive-capable base). */
static CK_RV gen_pair(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE *pub,
                      CK_OBJECT_HANDLE *priv) {
  CK_OBJECT_CLASS pubCls = CKO_PUBLIC_KEY, privCls = CKO_PRIVATE_KEY;
  CK_KEY_TYPE kt = CKK_X9_42_DH;
  CK_MECHANISM m;
  CK_ATTRIBUTE pubT[] = {
    { CKA_CLASS, &pubCls, sizeof(pubCls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_PRIME, (CK_VOID_PTR)P_X942, sizeof(P_X942) },
    { CKA_BASE, (CK_VOID_PTR)G_X942, sizeof(G_X942) },
    { CKA_SUBPRIME, (CK_VOID_PTR)Q_X942, sizeof(Q_X942) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) }
  };
  CK_ATTRIBUTE privT[] = {
    { CKA_CLASS, &privCls, sizeof(privCls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
    { CKA_DERIVE, &bTrue, sizeof(bTrue) }
  };
  m.mechanism = CKM_X9_42_DH_KEY_PAIR_GEN;
  m.pParameter = NULL_PTR;
  m.ulParameterLen = 0;
  *pub = 0;
  *priv = 0;
  return f->C_GenerateKeyPair(s, &m, pubT, 6, privT, 7, pub, priv);
}

/* Read one attribute through a length query into a canary-guarded
 * buffer; *n reports the value length. */
static CK_RV read_attr(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                       CK_ATTRIBUTE_TYPE t, CK_BYTE *out, CK_ULONG cap,
                       CK_ULONG *n) {
  CK_BYTE buf[MAX_PUB + 2u * GUARD];
  CK_ATTRIBUTE g[] = { { 0, NULL_PTR, 0 } };
  CK_ULONG i;
  CK_RV rv;
  if (cap == 0u || cap > MAX_PUB) {
    CHECK(0, "read_attr: bad cap %lu", (unsigned long)cap);
    return CKR_ARGUMENTS_BAD;
  }
  g[0].type = t;
  rv = f->C_GetAttributeValue(s, h, g, 1);
  if (rv != CKR_OK) {
    return rv;
  }
  if (g[0].ulValueLen > cap) {
    CHECK(0, "read_attr: length %lu over cap %lu",
          (unsigned long)g[0].ulValueLen, (unsigned long)cap);
    return CKR_ARGUMENTS_BAD;
  }
  memset(buf, CANARY, sizeof(buf));
  g[0].pValue = buf + GUARD;
  g[0].ulValueLen = cap;
  rv = f->C_GetAttributeValue(s, h, g, 1);
  if (rv != CKR_OK) {
    return rv;
  }
  for (i = 0; i < GUARD; i++) {
    CHECK(buf[i] == CANARY, "under-write guard clobbered at %lu",
          (unsigned long)i);
  }
  for (i = 0; i < (CK_ULONG)(sizeof(buf)) - GUARD - g[0].ulValueLen; i++) {
    CHECK(buf[GUARD + g[0].ulValueLen + i] == CANARY,
          "over-write guard clobbered at %lu", (unsigned long)i);
  }
  memcpy(out, buf + GUARD, g[0].ulValueLen);
  *n = g[0].ulValueLen;
  return CKR_OK;
}

/* Derive one AES object under CKM_X9_42_DH_DERIVE; *ph is zeroed
 * first so a refusal provably writes no handle. */
static CK_RV derive_aes(CK_SESSION_HANDLE s, CK_X9_42_DH_KDF_TYPE kdf,
                        CK_BYTE *other, CK_ULONG other_len,
                        CK_BYTE *peer, CK_ULONG peer_len,
                        CK_OBJECT_HANDLE base, CK_OBJECT_HANDLE *ph) {
  CK_OBJECT_CLASS dcls = CKO_SECRET_KEY;
  CK_KEY_TYPE dkt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_ATTRIBUTE dt[] = {
    { CKA_CLASS, &dcls, sizeof(dcls) },
    { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
    { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
    { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
  };
  CK_X9_42_DH1_DERIVE_PARAMS xp;
  CK_MECHANISM m;
  xp.kdf = kdf;
  xp.ulOtherInfoLen = other_len;
  xp.pOtherInfo = other;
  xp.ulPublicDataLen = peer_len;
  xp.pPublicData = peer;
  m.mechanism = CKM_X9_42_DH_DERIVE;
  m.pParameter = &xp;
  m.ulParameterLen = sizeof(xp);
  *ph = 0;
  return f->C_DeriveKey(s, &m, base, dt, 8, ph);
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE pubA = 0, privA = 0, pubB = 0, privB = 0;
  CK_OBJECT_HANDLE pubC = 0, privC = 0;
  CK_OBJECT_HANDLE hAB = 0, hBA = 0, hCA = 0, hbad = 0;
  CK_BYTE yA[MAX_PUB], yB[MAX_PUB];
  CK_ULONG yAn = 0, yBn = 0;
  CK_BYTE kAB[16], kBA[16], kCA[16];
  CK_ULONG kABn = 0, kBAn = 0, kCAn = 0;
  CK_BYTE yOne[1] = { 0x01 };
  CK_BYTE otherInfo[] = { 'x', '9', '4', '2', '-', 'o', 't', 'h', 'e', 'r' };
  char hx[2u * MAX_PUB + 1], hx2[2u * MAX_PUB + 1];

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

  CHECK(sizeof(P_X942) == 128u && sizeof(G_X942) == 128u &&
        sizeof(Q_X942) == 28u, "domain widths");

  /* ---- three key pairs on the pinned domain ---- */
  rv = gen_pair(sess, &pubA, &privA);
  printf("setup: GenerateKeyPair(A) rv=0x%lx pub=%lu priv=%lu\n",
         (unsigned long)rv, (unsigned long)pubA, (unsigned long)privA);
  CHECK(rv == CKR_OK && pubA != 0 && privA != 0, "keygen A");
  rv = gen_pair(sess, &pubB, &privB);
  printf("setup: GenerateKeyPair(B) rv=0x%lx pub=%lu priv=%lu\n",
         (unsigned long)rv, (unsigned long)pubB, (unsigned long)privB);
  CHECK(rv == CKR_OK && pubB != 0 && privB != 0, "keygen B");
  rv = gen_pair(sess, &pubC, &privC);
  printf("setup: GenerateKeyPair(C) rv=0x%lx pub=%lu priv=%lu\n",
         (unsigned long)rv, (unsigned long)pubC, (unsigned long)privC);
  CHECK(rv == CKR_OK && pubC != 0 && privC != 0, "keygen C");
  if (pubA == 0 || privA == 0 || pubB == 0 || privB == 0 ||
      pubC == 0 || privC == 0) {
    return 1;
  }
  rv = read_attr(sess, pubA, CKA_VALUE, yA, sizeof(yA), &yAn);
  printf("setup: read CKA_VALUE(pubA) rv=0x%lx n=%lu\n",
         (unsigned long)rv, (unsigned long)yAn);
  CHECK(rv == CKR_OK, "read pubA value");
  rv = read_attr(sess, pubB, CKA_VALUE, yB, sizeof(yB), &yBn);
  printf("setup: read CKA_VALUE(pubB) rv=0x%lx n=%lu\n",
         (unsigned long)rv, (unsigned long)yBn);
  CHECK(rv == CKR_OK, "read pubB value");
  if (rv != CKR_OK || yAn == 0u || yBn == 0u) {
    return 1;
  }
  hex_of(yA, yAn, hx);
  hex_of(yB, yBn, hx2);
  printf("crypto: pubA=%s\ncrypto: pubB=%s\n", hx, hx2);
  CHECK(yAn <= 128u && yBn <= 128u, "peer widths within the prime");
  CHECK(!(yAn == yBn && memcmp(yA, yB, yAn) == 0),
        "peers differ (randomized keygen)");

  /* ---- positive: both parties derive the same AES key ---- */
  rv = derive_aes(sess, CKD_NULL, NULL_PTR, 0, yB, yBn, privA, &hAB);
  printf("call: derive(A x B) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hAB);
  CHECK(rv == CKR_OK && hAB != 0, "A-side derive");
  rv = derive_aes(sess, CKD_NULL, NULL_PTR, 0, yA, yAn, privB, &hBA);
  printf("call: derive(B x A) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hBA);
  CHECK(rv == CKR_OK && hBA != 0, "B-side derive");
  if (hAB == 0 || hBA == 0) {
    return 1;
  }
  rv = read_attr(sess, hAB, CKA_VALUE, kAB, sizeof(kAB), &kABn);
  printf("result: read CKA_VALUE(AxB) rv=0x%lx n=%lu\n",
         (unsigned long)rv, (unsigned long)kABn);
  CHECK(rv == CKR_OK && kABn == 16u, "read A-side key");
  rv = read_attr(sess, hBA, CKA_VALUE, kBA, sizeof(kBA), &kBAn);
  printf("result: read CKA_VALUE(BxA) rv=0x%lx n=%lu\n",
         (unsigned long)rv, (unsigned long)kBAn);
  CHECK(rv == CKR_OK && kBAn == 16u, "read B-side key");
  if (rv != CKR_OK || kABn != 16u || kBAn != 16u) {
    return 1;
  }
  hex_of(kAB, sizeof(kAB), hx);
  hex_of(kBA, sizeof(kBA), hx2);
  printf("crypto: key(AxB)=%s\ncrypto: key(BxA)=%s\n", hx, hx2);
  CHECK(memcmp(kAB, kBA, sizeof(kAB)) == 0,
        "both parties derive the same AES key");

  /* ---- a different exchange derives a different key ---- */
  rv = derive_aes(sess, CKD_NULL, NULL_PTR, 0, yA, yAn, privC, &hCA);
  printf("call: derive(C x A) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hCA);
  CHECK(rv == CKR_OK && hCA != 0, "C-side derive");
  if (rv == CKR_OK && hCA != 0) {
    rv = read_attr(sess, hCA, CKA_VALUE, kCA, sizeof(kCA), &kCAn);
    printf("result: read CKA_VALUE(CxA) rv=0x%lx n=%lu\n",
           (unsigned long)rv, (unsigned long)kCAn);
    CHECK(rv == CKR_OK && kCAn == 16u, "read C-side key");
    if (rv == CKR_OK && kCAn == 16u) {
      hex_of(kCA, sizeof(kCA), hx);
      printf("crypto: key(CxA)=%s\n", hx);
      CHECK(memcmp(kCA, kAB, sizeof(kCA)) != 0,
            "a different exchange derives a different key");
    }
  }

  /* ---- the derived key encrypts and decrypts ---- */
  {
    CK_MECHANISM em;
    CK_BYTE pt[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    CK_BYTE ct[16], back[16];
    CK_ULONG ctn = sizeof(ct), backn = sizeof(back);
    em.mechanism = CKM_AES_ECB;
    em.pParameter = NULL_PTR;
    em.ulParameterLen = 0;
    rv = f->C_EncryptInit(sess, &em, hAB);
    printf("call: EncryptInit(AES-ECB, AxB) rv=0x%lx\n", (unsigned long)rv);
    CHECK(rv == CKR_OK, "encrypt init on the derived key");
    if (rv == CKR_OK) {
      rv = f->C_Encrypt(sess, pt, sizeof(pt), ct, &ctn);
      printf("call: Encrypt rv=0x%lx n=%lu\n",
             (unsigned long)rv, (unsigned long)ctn);
      CHECK(rv == CKR_OK && ctn == 16u, "encrypt one block");
    }
    if (rv == CKR_OK && ctn == 16u) {
      rv = f->C_DecryptInit(sess, &em, hAB);
      printf("call: DecryptInit(AES-ECB, AxB) rv=0x%lx\n",
             (unsigned long)rv);
      CHECK(rv == CKR_OK, "decrypt init on the derived key");
    }
    if (rv == CKR_OK) {
      rv = f->C_Decrypt(sess, ct, ctn, back, &backn);
      printf("call: Decrypt rv=0x%lx n=%lu\n",
             (unsigned long)rv, (unsigned long)backn);
      CHECK(rv == CKR_OK && backn == 16u, "decrypt one block");
      if (rv == CKR_OK && backn == 16u) {
        CHECK(memcmp(back, pt, sizeof(pt)) == 0, "ECB round-trip");
        CHECK(memcmp(ct, pt, sizeof(pt)) != 0, "ciphertext differs");
      }
    }
  }

  /* ---- negative legs: exact refusal, no handle (base privA is
   * proved derive-capable above, so each refusal is
   * parameter-caused) ---- */
  rv = derive_aes(sess, CKD_NULL, NULL_PTR, 0, NULL_PTR, 0, privA, &hbad);
  printf("call: derive(missing peer) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "missing peer refused typed without a handle");
  rv = derive_aes(sess, CKD_NULL, NULL_PTR, 0, yOne, sizeof(yOne),
                  privA, &hbad);
  printf("call: derive(y=1) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "malformed peer refused typed without a handle");
  rv = derive_aes(sess, CKD_NULL, otherInfo, sizeof(otherInfo), yB, yBn,
                  privA, &hbad);
  printf("call: derive(CKD_NULL + OtherInfo) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "CKD_NULL with OtherInfo refused typed without a handle");
  rv = derive_aes(sess, CKD_SHA1_KDF_ASN1, NULL_PTR, 0, yB, yBn,
                  privA, &hbad);
  printf("call: derive(ASN1 KDF, missing OtherInfo) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "ASN1 KDF without OtherInfo refused typed without a handle");
  rv = derive_aes(sess, 0x00009999UL, NULL_PTR, 0, yB, yBn, privA, &hbad);
  printf("call: derive(invalid KDF) rv=0x%lx h=%lu\n",
         (unsigned long)rv, (unsigned long)hbad);
  CHECK(rv == CKR_MECHANISM_PARAM_INVALID && hbad == 0,
        "invalid KDF refused typed without a handle");

  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok (rv=0x%lx)", (unsigned long)rv);

  if (g_failures != 0) {
    printf("consumer_x942_derive: %d FAILURE(S)\n", g_failures);
    return 1;
  }
  printf("consumer_x942_derive: PASS\n");
  return 0;
}
