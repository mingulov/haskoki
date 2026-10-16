/* tests/c/consumer_copy_policy.c — C_CopyObject enforces the set path's policy.
 *
 * A copy template is validated attribute by attribute through the same
 * per-attribute policy C_SetAttributeValue applies to the source: key
 * material, components, params, TRUSTED, ALWAYS_AUTHENTICATE,
 * ALLOWED_MECHANISMS, and any change on a MODIFIABLE=false source
 * (outside the copy exemptions) are refused with
 * CKR_ATTRIBUTE_READ_ONLY, with no handle and no new object. The
 * wrap-then-decrypt chain is shown impossible end to end: the
 * decrypt-capable copy is refused, the original cannot decrypt, and
 * no evil copy exists. Exemptions (TOKEN, PRIVATE, MODIFIABLE,
 * DESTROYABLE, COPYABLE-to-false), tightening (SENSITIVE up,
 * EXTRACTABLE down), and same-value overrides still work.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_copy_policy <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include "pkcs11.h"

#include <dlfcn.h>
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

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

static CK_OBJECT_HANDLE g_leaked[64];
static int g_nleaked = 0;

static void track(CK_OBJECT_HANDLE h) {
  if (h != 0 && g_nleaked < 64) {
    g_leaked[g_nleaked++] = h;
  }
}

static CK_ULONG count_all(CK_SESSION_HANDLE s, const char *what) {
  CK_OBJECT_HANDLE found[64];
  CK_ULONG total = 0, n = 0;
  CK_RV rv = f->C_FindObjectsInit(s, NULL_PTR, 0);
  CHECK(rv == CKR_OK, "find-all init %s (rv=0x%lx)", what, (unsigned long)rv);
  if (rv != CKR_OK) {
    return 9999;
  }
  do {
    n = 0;
    rv = f->C_FindObjects(s, found, 64, &n);
    CHECK(rv == CKR_OK, "find-all %s (rv=0x%lx)", what, (unsigned long)rv);
    if (rv != CKR_OK) {
      break;
    }
    total += n;
  } while (n == 64);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "find-all final %s (rv=0x%lx)", what, (unsigned long)rv);
  return total;
}

static void check_refused(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE src,
                          CK_ATTRIBUTE *over, CK_ULONG nover,
                          const char *what) {
  CK_ULONG before = count_all(s, what);
  CK_OBJECT_HANDLE h2 = 0;
  CK_ULONG after = 0;
  CK_RV rv = f->C_CopyObject(s, src, over, nover, &h2);
  if (h2 != 0) {
    track(h2);
  }
  CHECK(rv == CKR_ATTRIBUTE_READ_ONLY && h2 == 0,
        "%s refused read-only (rv=0x%lx h=%lu)", what, (unsigned long)rv,
        (unsigned long)h2);
  after = count_all(s, what);
  CHECK(after == before, "%s leaves the count unchanged (%lu -> %lu)", what,
        (unsigned long)before, (unsigned long)after);
}

static void fill_pat(CK_BYTE *p, CK_ULONG n, unsigned tag) {
  CK_ULONG j;
  for (j = 0; j < n; j++) {
    p[j] = (CK_BYTE)(tag + j * 31);
  }
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_CLASS privcls = CKO_PRIVATE_KEY, seckls = CKO_SECRET_KEY;
  CK_OBJECT_CLASS datacls = CKO_DATA;
  CK_KEY_TYPE rsakt = CKK_RSA, aeskt = CKK_AES, eckt = CKK_EC;
  CK_KEY_TYPE mldsa = CKK_ML_DSA, genkt = CKK_GENERIC_SECRET;
  CK_ULONG mldsa44 = CKP_ML_DSA_44;
  CK_OBJECT_HANDLE sensAes = 0, sensRsa = 0, ecPriv = 0, pqcPriv = 0;
  CK_OBJECT_HANDLE authKey = 0, wrapKey = 0, targetKey = 0, nonmod = 0;
  CK_OBJECT_HANDLE trustedSrc = 0;
  int i;

  static CK_BYTE mod[] = "copy-policy-modulus";
  static CK_BYTE pub[] = "copy-policy-pubexp";
  static CK_BYTE prv[] = "copy-policy-privexp";
  static CK_BYTE p1[] = "copy-policy-p1";
  static CK_BYTE p2[] = "copy-policy-p2";
  static CK_BYTE e1[] = "copy-policy-e1";
  static CK_BYTE e2[] = "copy-policy-e2";
  static CK_BYTE cc[] = "copy-policy-cc";
  static CK_BYTE kval[16] = { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                              0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
  static CK_BYTE kval2[16] = { 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e,
                               0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e };
  static CK_BYTE forgedMod[] = "copy-policy-forged-modulus";
  static CK_BYTE forgedPrv[] = "copy-policy-forged-privexp";
  /* P-256 and P-384 EC_PARAMS DER. */
  static CK_BYTE p256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
                            0x3D, 0x03, 0x01, 0x07 };
  static CK_BYTE p384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
  static CK_BYTE escalar[32] = { 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                                 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                                 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                                 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07 };
  static CK_BYTE escpw[32] = { 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                               0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                               0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                               0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09 };
  static CK_BYTE dsaVal[2560];
  static CK_BYTE dsaSeed[32], dsaSeedForged[32];
  static CK_BYTE targVal[16] = { 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
                                 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3 };
  /* ALLOWED_MECHANISMS wire order is little-endian u64s. */
  static CK_BYTE allowWrap[8] = { 0x09, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static CK_BYTE allowBoth[16] = { 0x09, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static CK_BYTE allowDec[8] = { 0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  fill_pat(dsaVal, sizeof(dsaVal), 11);
  fill_pat(dsaSeed, sizeof(dsaSeed), 21);
  fill_pat(dsaSeedForged, sizeof(dsaSeedForged), 99);

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
  CHECK(rv == CKR_OK, "C_Initialize ok");
  rv = f->C_GetSlotList(CK_FALSE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots >= 1, "slot present");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok");
  rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECK(rv == CKR_OK, "Login user ok");

  /* Sensitive AES secret. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_VALUE, kval, sizeof(kval) }
    };
    rv = f->C_CreateObject(sess, t, 6, &sensAes);
    CHECK(rv == CKR_OK && sensAes != 0, "sensitive AES imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Sensitive RSA private. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_MODULUS, mod, sizeof(mod) - 1 },
      { CKA_PUBLIC_EXPONENT, pub, sizeof(pub) - 1 },
      { CKA_PRIVATE_EXPONENT, prv, sizeof(prv) - 1 },
      { CKA_PRIME_1, p1, sizeof(p1) - 1 },
      { CKA_PRIME_2, p2, sizeof(p2) - 1 },
      { CKA_EXPONENT_1, e1, sizeof(e1) - 1 },
      { CKA_EXPONENT_2, e2, sizeof(e2) - 1 },
      { CKA_COEFFICIENT, cc, sizeof(cc) - 1 }
    };
    rv = f->C_CreateObject(sess, t, 13, &sensRsa);
    CHECK(rv == CKR_OK && sensRsa != 0, "sensitive RSA imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Sensitive EC private (P-256). */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &eckt, sizeof(eckt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_EC_PARAMS, p256, sizeof(p256) },
      { CKA_VALUE, escalar, sizeof(escalar) }
    };
    rv = f->C_CreateObject(sess, t, 7, &ecPriv);
    CHECK(rv == CKR_OK && ecPriv != 0, "sensitive EC imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Sensitive ML-DSA private. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &mldsa, sizeof(mldsa) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_PARAMETER_SET, &mldsa44, sizeof(mldsa44) },
      { CKA_VALUE, dsaVal, sizeof(dsaVal) },
      { CKA_SEED, dsaSeed, sizeof(dsaSeed) }
    };
    rv = f->C_CreateObject(sess, t, 8, &pqcPriv);
    CHECK(rv == CKR_OK && pqcPriv != 0, "sensitive ML-DSA imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Always-authenticate signing key. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_ALWAYS_AUTHENTICATE, &bTrue, sizeof(bTrue) },
      { CKA_MODULUS, mod, sizeof(mod) - 1 },
      { CKA_PUBLIC_EXPONENT, pub, sizeof(pub) - 1 },
      { CKA_PRIVATE_EXPONENT, prv, sizeof(prv) - 1 },
      { CKA_PRIME_1, p1, sizeof(p1) - 1 },
      { CKA_PRIME_2, p2, sizeof(p2) - 1 },
      { CKA_EXPONENT_1, e1, sizeof(e1) - 1 },
      { CKA_EXPONENT_2, e2, sizeof(e2) - 1 },
      { CKA_COEFFICIENT, cc, sizeof(cc) - 1 }
    };
    rv = f->C_CreateObject(sess, t, 13, &authKey);
    CHECK(rv == CKR_OK && authKey != 0, "auth key imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Wrap-only key with mechanisms pinned to wrap. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_WRAP, &bTrue, sizeof(bTrue) },
      { CKA_DECRYPT, &bFalse, sizeof(bFalse) },
      { CKA_ALLOWED_MECHANISMS, allowWrap, sizeof(allowWrap) },
      { CKA_VALUE, kval, sizeof(kval) }
    };
    rv = f->C_CreateObject(sess, t, 7, &wrapKey);
    CHECK(rv == CKR_OK && wrapKey != 0, "wrap key imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Sensitive, extractable wrap target. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_VALUE, targVal, sizeof(targVal) }
    };
    rv = f->C_CreateObject(sess, t, 6, &targetKey);
    CHECK(rv == CKR_OK && targetKey != 0, "target key imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Non-modifiable key. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_MODIFIABLE, &bFalse, sizeof(bFalse) },
      { CKA_DECRYPT, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"nonmod-a", 8 },
      { CKA_VALUE, kval, sizeof(kval) }
    };
    rv = f->C_CreateObject(sess, t, 7, &nonmod);
    CHECK(rv == CKR_OK && nonmod != 0, "non-modifiable imports (rv=0x%lx)",
          (unsigned long)rv);
    (void)genkt;
    (void)datacls;
  }

  if (sensAes != 0 && sensRsa != 0 && ecPriv != 0 && pqcPriv != 0 &&
      authKey != 0 && wrapKey != 0 && targetKey != 0 && nonmod != 0) {
    CK_ATTRIBUTE vOver[] = { { CKA_VALUE, kval2, sizeof(kval2) } };
    CK_ATTRIBUTE modOver[] = { { CKA_MODULUS, forgedMod, sizeof(forgedMod) - 1 } };
    CK_ATTRIBUTE prvOver[] = { { CKA_PRIVATE_EXPONENT, forgedPrv, sizeof(forgedPrv) - 1 } };
    CK_ATTRIBUTE ecValOver[] = { { CKA_VALUE, escpw, sizeof(escpw) } };
    CK_ATTRIBUTE ecParOver[] = { { CKA_EC_PARAMS, p384, sizeof(p384) } };
    CK_ATTRIBUTE seedOver[] = { { CKA_SEED, dsaSeedForged, sizeof(dsaSeedForged) } };
    CK_ATTRIBUTE trustOver[] = { { CKA_TRUSTED, &bTrue, sizeof(bTrue) } };
    CK_ATTRIBUTE authOver[] = { { CKA_ALWAYS_AUTHENTICATE, &bFalse, sizeof(bFalse) } };
    CK_ATTRIBUTE allowOver[] = { { CKA_ALLOWED_MECHANISMS, allowBoth, sizeof(allowBoth) } };
    CK_ATTRIBUTE decOver[] = { { CKA_DECRYPT, &bTrue, sizeof(bTrue) } };
    CK_ATTRIBUTE lblOver[] = { { CKA_LABEL, (CK_VOID_PTR)"nonmod-b", 8 } };

    check_refused(sess, sensAes, vOver, 1, "sensitive AES + VALUE");
    check_refused(sess, sensRsa, modOver, 1, "sensitive RSA + MODULUS");
    check_refused(sess, sensRsa, prvOver, 1, "sensitive RSA + PRIVATE_EXPONENT");
    check_refused(sess, ecPriv, ecValOver, 1, "sensitive EC + VALUE");
    check_refused(sess, ecPriv, ecParOver, 1, "sensitive EC + EC_PARAMS relabel");
    check_refused(sess, pqcPriv, seedOver, 1, "sensitive ML-DSA + SEED");
    check_refused(sess, sensAes, trustOver, 1, "sensitive AES + TRUSTED=true forged");
    check_refused(sess, authKey, authOver, 1, "auth key + ALWAYS_AUTHENTICATE drop");
    check_refused(sess, wrapKey, allowOver, 1, "wrap key + ALLOWED widen");
    check_refused(sess, nonmod, decOver, 1, "non-modifiable + DECRYPT");
    check_refused(sess, nonmod, lblOver, 1, "non-modifiable + LABEL");

    /* The wrap-then-decrypt chain: the decrypt-capable widened copy
     * is refused, so no evil copy exists. */
    {
      CK_ATTRIBUTE evil[] = {
        { CKA_ALLOWED_MECHANISMS, allowDec, sizeof(allowDec) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, (CK_VOID_PTR)"evil-copy", 9 }
      };
      CK_ULONG before = count_all(sess, "evil-copy");
      CK_OBJECT_HANDLE h2 = 0;
      CK_OBJECT_HANDLE found[8];
      CK_ULONG n = 0;
      CK_ATTRIBUTE q[] = { { CKA_LABEL, (CK_VOID_PTR)"evil-copy", 9 } };
      rv = f->C_CopyObject(sess, wrapKey, evil, 3, &h2);
      if (h2 != 0) {
        track(h2);
      }
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY && h2 == 0,
            "evil copy refused read-only (rv=0x%lx h=%lu)",
            (unsigned long)rv, (unsigned long)h2);
      CHECK(count_all(sess, "evil-copy") == before,
            "evil copy leaves the count unchanged");
      rv = f->C_FindObjectsInit(sess, q, 1);
      CHECK(rv == CKR_OK, "evil find init (rv=0x%lx)", (unsigned long)rv);
      rv = f->C_FindObjects(sess, found, 8, &n);
      CHECK(rv == CKR_OK && n == 0, "no evil copy exists (n=%lu)",
            (unsigned long)n);
      rv = f->C_FindObjectsFinal(sess);
      CHECK(rv == CKR_OK, "evil find final (rv=0x%lx)", (unsigned long)rv);
      /* The original cannot decrypt either: end-to-end impossible. */
      {
        CK_MECHANISM mech;
        mech.mechanism = CKM_AES_ECB;
        mech.pParameter = NULL_PTR;
        mech.ulParameterLen = 0;
        rv = f->C_DecryptInit(sess, &mech, wrapKey);
        CHECK(rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
              "original cannot decrypt (rv=0x%lx)", (unsigned long)rv);
      }
    }

    /* Positive: exemptions on a non-modifiable source still work. */
    {
      CK_ATTRIBUTE tokOver[] = { { CKA_TOKEN, &bTrue, sizeof(bTrue) } };
      CK_ATTRIBUTE privOver[] = { { CKA_PRIVATE, &bTrue, sizeof(bTrue) } };
      CK_ATTRIBUTE modOver2[] = { { CKA_MODIFIABLE, &bTrue, sizeof(bTrue) } };
      CK_ATTRIBUTE desOver[] = { { CKA_DESTROYABLE, &bFalse, sizeof(bFalse) } };
      CK_ATTRIBUTE cpyOver[] = { { CKA_COPYABLE, &bFalse, sizeof(bFalse) } };
      CK_OBJECT_HANDLE h2 = 0;
      rv = f->C_CopyObject(sess, nonmod, tokOver, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod TOKEN exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
      rv = f->C_CopyObject(sess, nonmod, privOver, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod PRIVATE exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
      rv = f->C_CopyObject(sess, nonmod, modOver2, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod MODIFIABLE exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
      rv = f->C_CopyObject(sess, nonmod, desOver, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod DESTROYABLE exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
      rv = f->C_CopyObject(sess, nonmod, cpyOver, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod COPYABLE exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
    }

    /* Positive: tightening still works. */
    {
      CK_OBJECT_HANDLE h2 = 0;
      CK_ATTRIBUTE sensUp[] = { { CKA_SENSITIVE, &bTrue, sizeof(bTrue) } };
      CK_ATTRIBUTE extrDown[] = { { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) } };
      CK_ATTRIBUTE tOpen[] = {
        { CKA_CLASS, &seckls, sizeof(seckls) },
        { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_VALUE, kval, sizeof(kval) }
      };
      CK_OBJECT_HANDLE openAes = 0;
      rv = f->C_CreateObject(sess, tOpen, 6, &openAes);
      CHECK(rv == CKR_OK && openAes != 0, "open AES imports (rv=0x%lx)",
            (unsigned long)rv);
      if (openAes != 0) {
        track(openAes);
        rv = f->C_CopyObject(sess, openAes, sensUp, 1, &h2);
        CHECK(rv == CKR_OK && h2 != 0, "SENSITIVE tighten works (rv=0x%lx)",
              (unsigned long)rv);
        if (h2 != 0) { track(h2); h2 = 0; }
        rv = f->C_CopyObject(sess, openAes, extrDown, 1, &h2);
        CHECK(rv == CKR_OK && h2 != 0, "EXTRACTABLE tighten works (rv=0x%lx)",
              (unsigned long)rv);
        if (h2 != 0) { track(h2); h2 = 0; }
      }
    }

    /* Positive: same-value overrides still work. */
    {
      CK_OBJECT_HANDLE h2 = 0;
      CK_ATTRIBUTE sameVal[] = { { CKA_VALUE, kval, sizeof(kval) } };
      CK_ATTRIBUTE sameMod[] = { { CKA_MODULUS, mod, sizeof(mod) - 1 } };
      rv = f->C_CopyObject(sess, sensAes, sameVal, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "same VALUE works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
      rv = f->C_CopyObject(sess, sensRsa, sameMod, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "same MODULUS works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
    }
  }

  /* TRUSTED inheritance: an SO-created TRUSTED source copied with an
   * empty template by the user is refused. */
  {
    CK_OBJECT_CLASS dcls = CKO_DATA;
    CK_OBJECT_HANDLE h2 = 0;
    CK_ULONG before = 0, after = 0;
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "Logout before SO");
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
    CHECK(rv == CKR_OK, "Login SO ok (rv=0x%lx)", (unsigned long)rv);
    {
      CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &dcls, sizeof(dcls) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"trusted-src", 11 },
        { CKA_TRUSTED, &bTrue, sizeof(bTrue) }
      };
      rv = f->C_CreateObject(sess, t, 4, &trustedSrc);
      CHECK(rv == CKR_OK && trustedSrc != 0,
            "SO TRUSTED source imports (rv=0x%lx)", (unsigned long)rv);
    }
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "SO logout ok");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    CHECK(rv == CKR_OK, "re-login user ok");
    if (trustedSrc != 0) {
      before = count_all(sess, "trusted-inherit");
      rv = f->C_CopyObject(sess, trustedSrc, NULL_PTR, 0, &h2);
      if (h2 != 0) {
        track(h2);
      }
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY && h2 == 0,
            "TRUSTED inherit refused read-only (rv=0x%lx h=%lu)",
            (unsigned long)rv, (unsigned long)h2);
      after = count_all(sess, "trusted-inherit");
      CHECK(after == before, "TRUSTED inherit leaves count unchanged");
    }
  }

  for (i = 0; i < g_nleaked; i++) {
    rv = f->C_DestroyObject(sess, g_leaked[i]);
    CHECK(rv == CKR_OK || rv == CKR_OBJECT_HANDLE_INVALID ||
          rv == CKR_ACTION_PROHIBITED,
          "copy destroyed (rv=0x%lx)", (unsigned long)rv);
  }
  if (sensAes != 0) {
    rv = f->C_DestroyObject(sess, sensAes);
    CHECK(rv == CKR_OK, "sensitive AES destroyed");
  }
  if (sensRsa != 0) {
    rv = f->C_DestroyObject(sess, sensRsa);
    CHECK(rv == CKR_OK, "sensitive RSA destroyed");
  }
  if (ecPriv != 0) {
    rv = f->C_DestroyObject(sess, ecPriv);
    CHECK(rv == CKR_OK, "sensitive EC destroyed");
  }
  if (pqcPriv != 0) {
    rv = f->C_DestroyObject(sess, pqcPriv);
    CHECK(rv == CKR_OK, "sensitive ML-DSA destroyed");
  }
  if (authKey != 0) {
    rv = f->C_DestroyObject(sess, authKey);
    CHECK(rv == CKR_OK, "auth key destroyed");
  }
  if (wrapKey != 0) {
    rv = f->C_DestroyObject(sess, wrapKey);
    CHECK(rv == CKR_OK, "wrap key destroyed");
  }
  if (targetKey != 0) {
    rv = f->C_DestroyObject(sess, targetKey);
    CHECK(rv == CKR_OK, "target key destroyed");
  }
  if (nonmod != 0) {
    rv = f->C_DestroyObject(sess, nonmod);
    CHECK(rv == CKR_OK, "non-modifiable destroyed");
  }
  if (trustedSrc != 0) {
    rv = f->C_DestroyObject(sess, trustedSrc);
    CHECK(rv == CKR_OK || rv == CKR_OBJECT_HANDLE_INVALID,
          "trusted source destroyed (rv=0x%lx)", (unsigned long)rv);
  }

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_copy_policy (copy enforces the set policy)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
