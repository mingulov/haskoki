/* tests/c/consumer_copy_policy.c — C_CopyObject enforces the set path's policy.
 *
 * A copy template is validated attribute by attribute through the same
 * per-attribute policy C_SetAttributeValue applies to the source: key
 * material, components, params, TRUSTED, ALWAYS_AUTHENTICATE,
 * ALLOWED_MECHANISMS, and any change on a MODIFIABLE=false source
 * (outside the copy exemptions) are refused with
 * CKR_ATTRIBUTE_READ_ONLY, with no handle and no new object.
 * Widening ALLOWED_MECHANISMS by copy is refused, the original
 * cannot decrypt, and no widened copy exists. Exemptions (TOKEN,
 * PRIVATE, DESTROYABLE, COPYABLE-to-false), MODIFIABLE tightening
 * only, TOKEN/DESTROYABLE free on copy, tightening (SENSITIVE up,
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

static void expect_bool_attr(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                             CK_ATTRIBUTE_TYPE t, CK_BBOOL want,
                             const char *what) {
  CK_BBOOL got = 0xa5;
  CK_ATTRIBUTE q[] = { { t, &got, sizeof(got) } };
  CK_RV rv = f->C_GetAttributeValue(s, h, q, 1);
  CHECK(rv == CKR_OK && got == want && q[0].ulValueLen == sizeof(got),
        "%s reads %s (rv=0x%lx)", what, want ? "true" : "false",
        (unsigned long)rv);
}

static void expect_ulong_attr(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                              CK_ATTRIBUTE_TYPE t, CK_ULONG want,
                              const char *what) {
  CK_ULONG got = 0;
  CK_ATTRIBUTE q[] = { { t, &got, sizeof(got) } };
  CK_RV rv = f->C_GetAttributeValue(s, h, q, 1);
  CHECK(rv == CKR_OK && got == want && q[0].ulValueLen == sizeof(got),
        "%s reads 0x%lx (rv=0x%lx)", what, (unsigned long)want,
        (unsigned long)rv);
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

    /* Widening ALLOWED_MECHANISMS by copy is refused, so no
     * widened copy exists. */
    {
      CK_ATTRIBUTE evil[] = {
        { CKA_ALLOWED_MECHANISMS, allowDec, sizeof(allowDec) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, (CK_VOID_PTR)"widened-copy", 12 }
      };
      CK_ULONG before = count_all(sess, "widened-copy");
      CK_OBJECT_HANDLE h2 = 0;
      CK_OBJECT_HANDLE found[8];
      CK_ULONG n = 0;
      CK_ATTRIBUTE q[] = { { CKA_LABEL, (CK_VOID_PTR)"widened-copy", 12 } };
      rv = f->C_CopyObject(sess, wrapKey, evil, 3, &h2);
      if (h2 != 0) {
        track(h2);
      }
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY && h2 == 0,
            "widened copy refused read-only (rv=0x%lx h=%lu)",
            (unsigned long)rv, (unsigned long)h2);
      CHECK(count_all(sess, "widened-copy") == before,
            "widened copy leaves the count unchanged");
      rv = f->C_FindObjectsInit(sess, q, 1);
      CHECK(rv == CKR_OK, "widened find init (rv=0x%lx)", (unsigned long)rv);
      rv = f->C_FindObjects(sess, found, 8, &n);
      CHECK(rv == CKR_OK && n == 0, "no widened copy exists (n=%lu)",
            (unsigned long)n);
      rv = f->C_FindObjectsFinal(sess);
      CHECK(rv == CKR_OK, "widened find final (rv=0x%lx)", (unsigned long)rv);
      /* The original cannot decrypt either. */
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

    /* Positive: exemptions on a non-modifiable source still work;
     * MODIFIABLE loosening is refused. */
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
      {
        CK_ULONG beforeMod = count_all(sess, "nonmod-modifiable");
        rv = f->C_CopyObject(sess, nonmod, modOver2, 1, &h2);
        if (h2 != 0) { track(h2); }
        CHECK(rv == CKR_ATTRIBUTE_READ_ONLY && h2 == 0,
              "nonmod MODIFIABLE loosen refused (rv=0x%lx h=%lu)",
              (unsigned long)rv, (unsigned long)h2);
        CHECK(count_all(sess, "nonmod-modifiable") == beforeMod,
              "nonmod MODIFIABLE loosen leaves count unchanged");
        h2 = 0;
      }
      rv = f->C_CopyObject(sess, nonmod, desOver, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod DESTROYABLE exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
      rv = f->C_CopyObject(sess, nonmod, cpyOver, 1, &h2);
      CHECK(rv == CKR_OK && h2 != 0, "nonmod COPYABLE exemption works (rv=0x%lx)",
            (unsigned long)rv);
      if (h2 != 0) { track(h2); h2 = 0; }
    }

    /* Two-step: MODIFIABLE loosen refused, so DECRYPT never set. */
    {
      CK_ATTRIBUTE looseOver[] = { { CKA_MODIFIABLE, &bTrue, sizeof(bTrue) } };
      CK_ATTRIBUTE decSet[] = { { CKA_DECRYPT, &bTrue, sizeof(bTrue) } };
      CK_OBJECT_HANDLE loose = 0;
      CK_ULONG before = count_all(sess, "loose-twostep");
      rv = f->C_CopyObject(sess, nonmod, looseOver, 1, &loose);
      if (loose != 0) { track(loose); }
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY && loose == 0,
            "nonmod two-step loosen refused (rv=0x%lx h=%lu)",
            (unsigned long)rv, (unsigned long)loose);
      CHECK(count_all(sess, "loose-twostep") == before,
            "nonmod two-step leaves count unchanged");
      if (rv == CKR_OK && loose != 0) {
        CK_RV rv2 = f->C_SetAttributeValue(sess, loose, decSet, 1);
        CHECK(rv2 != CKR_OK,
              "loosened copy must not accept DECRYPT (rv2=0x%lx)",
              (unsigned long)rv2);
      }
      rv = f->C_SetAttributeValue(sess, nonmod, decSet, 1);
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY,
            "nonmod source DECRYPT still refused (rv=0x%lx)",
            (unsigned long)rv);
    }

    /* Token to session: a token key copied with TOKEN=FALSE succeeds. */
    {
      CK_OBJECT_HANDLE tokSrc = 0, h2 = 0;
      CK_ATTRIBUTE tTok[] = {
        { CKA_CLASS, &seckls, sizeof(seckls) },
        { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, (CK_VOID_PTR)"tok-src", 7 },
        { CKA_VALUE, kval, sizeof(kval) }
      };
      CK_ATTRIBUTE demote[] = {
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"sess-copy", 9 }
      };
      CK_BBOOL got = 0;
      CK_ATTRIBUTE qTok[] = { { CKA_TOKEN, &got, sizeof(got) } };
      rv = f->C_CreateObject(sess, tTok, 5, &tokSrc);
      CHECK(rv == CKR_OK && tokSrc != 0, "token AES imports (rv=0x%lx)",
            (unsigned long)rv);
      if (tokSrc != 0) {
        track(tokSrc);
        rv = f->C_CopyObject(sess, tokSrc, demote, 2, &h2);
        CHECK(rv == CKR_OK && h2 != 0, "token to session works (rv=0x%lx)",
              (unsigned long)rv);
        if (h2 != 0) {
          track(h2);
          got = 0;
          qTok[0].ulValueLen = sizeof(got);
          rv = f->C_GetAttributeValue(sess, h2, qTok, 1);
          CHECK(rv == CKR_OK && qTok[0].ulValueLen == sizeof(got) && got == CK_FALSE,
                "copy is a session object (rv=0x%lx)", (unsigned long)rv);
          got = 0;
          qTok[0].ulValueLen = sizeof(got);
          rv = f->C_GetAttributeValue(sess, tokSrc, qTok, 1);
          CHECK(rv == CKR_OK && got == CK_TRUE,
                "source stays a token object (rv=0x%lx)", (unsigned long)rv);
          h2 = 0;
        }
      }
    }

    /* DESTROYABLE false to true on copy succeeds. */
    {
      CK_OBJECT_HANDLE nodesSrc = 0, h2 = 0;
      CK_ATTRIBUTE tNodes[] = {
        { CKA_CLASS, &datacls, sizeof(datacls) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"nodes-src", 9 },
        { CKA_DESTROYABLE, &bFalse, sizeof(bFalse) }
      };
      CK_ATTRIBUTE looseDes[] = { { CKA_DESTROYABLE, &bTrue, sizeof(bTrue) } };
      CK_BBOOL got = 0;
      CK_ATTRIBUTE qDes[] = { { CKA_DESTROYABLE, &got, sizeof(got) } };
      rv = f->C_CreateObject(sess, tNodes, 4, &nodesSrc);
      CHECK(rv == CKR_OK && nodesSrc != 0, "nodes data imports (rv=0x%lx)",
            (unsigned long)rv);
      if (nodesSrc != 0) {
        track(nodesSrc);
        rv = f->C_CopyObject(sess, nodesSrc, looseDes, 1, &h2);
        CHECK(rv == CKR_OK && h2 != 0, "destroyable loosen works (rv=0x%lx)",
              (unsigned long)rv);
        if (h2 != 0) {
          track(h2);
          got = 0;
          qDes[0].ulValueLen = sizeof(got);
          rv = f->C_GetAttributeValue(sess, h2, qDes, 1);
          CHECK(rv == CKR_OK && got == CK_TRUE,
                "copy is destroyable (rv=0x%lx)", (unsigned long)rv);
          got = 1;
          qDes[0].ulValueLen = sizeof(got);
          rv = f->C_GetAttributeValue(sess, nodesSrc, qDes, 1);
          CHECK(rv == CKR_OK && got == CK_FALSE,
                "source stays not destroyable (rv=0x%lx)", (unsigned long)rv);
          h2 = 0;
        }
      }
    }

    /* Data VALUE on a non-modifiable source is refused. */
    {
      CK_OBJECT_HANDLE dSrc = 0;
      CK_ATTRIBUTE tData[] = {
        { CKA_CLASS, &datacls, sizeof(datacls) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"d-nonmod", 8 },
        { CKA_MODIFIABLE, &bFalse, sizeof(bFalse) },
        { CKA_VALUE, (CK_VOID_PTR)"old", 3 }
      };
      CK_ATTRIBUTE vNew[] = { { CKA_VALUE, (CK_VOID_PTR)"new", 3 } };
      rv = f->C_CreateObject(sess, tData, 5, &dSrc);
      CHECK(rv == CKR_OK && dSrc != 0, "nonmod data imports (rv=0x%lx)",
            (unsigned long)rv);
      if (dSrc != 0) {
        track(dSrc);
        check_refused(sess, dSrc, vNew, 1, "nonmod data + VALUE");
      }
    }

    /* Sealed PRIVATE true to false on copy is refused. */
    {
      CK_OBJECT_HANDLE sealedPriv = 0;
      CK_ATTRIBUTE tSealed[] = {
        { CKA_CLASS, &seckls, sizeof(seckls) },
        { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, (CK_VOID_PTR)"sealed-priv", 11 },
        { CKA_VALUE, kval, sizeof(kval) }
      };
      CK_ATTRIBUTE pubOver[] = { { CKA_PRIVATE, &bFalse, sizeof(bFalse) } };
      rv = f->C_CreateObject(sess, tSealed, 8, &sealedPriv);
      CHECK(rv == CKR_OK && sealedPriv != 0, "sealed private imports (rv=0x%lx)",
            (unsigned long)rv);
      if (sealedPriv != 0) {
        track(sealedPriv);
        check_refused(sess, sealedPriv, pubOver, 1, "sealed key + PRIVATE to public");
      }
    }

    /* MODIFIABLE tightening on copy still works. */
    {
      CK_OBJECT_HANDLE modSrc = 0, h2 = 0;
      CK_ATTRIBUTE tMod[] = {
        { CKA_CLASS, &datacls, sizeof(datacls) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"mod-src", 7 },
        { CKA_MODIFIABLE, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE tighten[] = { { CKA_MODIFIABLE, &bFalse, sizeof(bFalse) } };
      CK_BBOOL got = 1;
      CK_ATTRIBUTE qMod[] = { { CKA_MODIFIABLE, &got, sizeof(got) } };
      rv = f->C_CreateObject(sess, tMod, 4, &modSrc);
      CHECK(rv == CKR_OK && modSrc != 0, "modifiable data imports (rv=0x%lx)",
            (unsigned long)rv);
      if (modSrc != 0) {
        track(modSrc);
        rv = f->C_CopyObject(sess, modSrc, tighten, 1, &h2);
        CHECK(rv == CKR_OK && h2 != 0, "modifiable tighten works (rv=0x%lx)",
              (unsigned long)rv);
        if (h2 != 0) {
          track(h2);
          got = 1;
          qMod[0].ulValueLen = sizeof(got);
          rv = f->C_GetAttributeValue(sess, h2, qMod, 1);
          CHECK(rv == CKR_OK && got == CK_FALSE,
                "tightened copy reads back (rv=0x%lx)", (unsigned long)rv);
          h2 = 0;
        }
      }
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

  /* ---- generated keys carry birth history; copies inherit it ---- */
  {
    CK_MECHANISM gm;
    CK_ULONG vlen = 16;
    CK_OBJECT_HANDLE gen = 0, gcopy = 0;
    CK_ATTRIBUTE gtmpl[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
    };
    gm.mechanism = CKM_AES_KEY_GEN;
    gm.pParameter = NULL_PTR;
    gm.ulParameterLen = 0;
    rv = f->C_GenerateKey(sess, &gm, gtmpl, 6, &gen);
    CHECK(rv == CKR_OK && gen != 0, "locked AES key generates");
    if (gen != 0) {
      track(gen);
      expect_bool_attr(sess, gen, CKA_SENSITIVE, CK_TRUE,
                       "generated SENSITIVE");
      expect_bool_attr(sess, gen, CKA_EXTRACTABLE, CK_FALSE,
                       "generated EXTRACTABLE");
      expect_bool_attr(sess, gen, CKA_ALWAYS_SENSITIVE, CK_TRUE,
                       "generated ALWAYS_SENSITIVE");
      expect_bool_attr(sess, gen, CKA_NEVER_EXTRACTABLE, CK_TRUE,
                       "generated NEVER_EXTRACTABLE");
      expect_bool_attr(sess, gen, CKA_LOCAL, CK_TRUE, "generated LOCAL");
      expect_ulong_attr(sess, gen, CKA_KEY_GEN_MECHANISM,
                        (CK_ULONG)CKM_AES_KEY_GEN, "generated KEY_GEN_MECHANISM");
      rv = f->C_CopyObject(sess, gen, NULL_PTR, 0, &gcopy);
      CHECK(rv == CKR_OK && gcopy != 0, "generated key copies");
      if (gcopy != 0) {
        track(gcopy);
        expect_bool_attr(sess, gcopy, CKA_SENSITIVE, CK_TRUE,
                         "generated-copy SENSITIVE");
        expect_bool_attr(sess, gcopy, CKA_EXTRACTABLE, CK_FALSE,
                         "generated-copy EXTRACTABLE");
        expect_bool_attr(sess, gcopy, CKA_ALWAYS_SENSITIVE, CK_TRUE,
                         "generated-copy ALWAYS_SENSITIVE");
        expect_bool_attr(sess, gcopy, CKA_NEVER_EXTRACTABLE, CK_TRUE,
                         "generated-copy NEVER_EXTRACTABLE");
        expect_bool_attr(sess, gcopy, CKA_LOCAL, CK_TRUE,
                         "generated-copy LOCAL");
        expect_ulong_attr(sess, gcopy, CKA_KEY_GEN_MECHANISM,
                          (CK_ULONG)CKM_AES_KEY_GEN,
                          "generated-copy KEY_GEN_MECHANISM");
      }
      {
        CK_ATTRIBUTE forge[] = {
          { CKA_LOCAL, &bFalse, sizeof(bFalse) }
        };
        check_refused(sess, gen, forge, 1, "generated LOCAL forge");
      }
      {
        CK_ATTRIBUTE forge[] = {
          { CKA_ALWAYS_SENSITIVE, &bFalse, sizeof(bFalse) }
        };
        check_refused(sess, gen, forge, 1, "generated ALWAYS_SENSITIVE forge");
      }
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
