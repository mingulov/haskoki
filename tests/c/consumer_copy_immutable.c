/* tests/c/consumer_copy_immutable.c — C_CopyObject refuses class/key-type rewrites.
 *
 * A sealed RSA private key (stored sensitive or stored
 * unextractable) and a sealed AES key (stored sensitive, stored
 * unextractable, or flag-less) copied with CKA_CLASS =
 * CKO_PUBLIC_KEY, CKA_CLASS = CKO_DATA, or a changed CKA_KEY_TYPE is
 * refused with CKR_ATTRIBUTE_READ_ONLY (the C_SetAttributeValue
 * code for these immutable attributes), with no handle emitted and
 * the object count unchanged. A copy carrying the same class and
 * key type still succeeds with a fresh handle.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_copy_immutable <path-to-libhaskoki.so>
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

/* Handles minted by refused copies (only when the refusal is
 * missing): tracked so cleanup stays complete either way. */
static CK_OBJECT_HANDLE g_leaked[32];
static int g_nleaked = 0;

static void track(CK_OBJECT_HANDLE h) {
  if (h != 0 && g_nleaked < 32) {
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

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_CLASS privcls = CKO_PRIVATE_KEY, pubcls = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS seckls = CKO_SECRET_KEY, datacls = CKO_DATA;
  CK_KEY_TYPE rsakt = CKK_RSA, aeskt = CKK_AES;
  CK_KEY_TYPE eckt = CKK_EC, genkt = CKK_GENERIC_SECRET;
  CK_OBJECT_HANDLE sensRsa = 0, unextRsa = 0, sensAes = 0, unextAes = 0;
  CK_OBJECT_HANDLE legacyAes = 0;
  int i;

  static CK_BYTE mod[] = "copy-immutable-modulus";
  static CK_BYTE pub[] = "copy-immutable-pubexp";
  static CK_BYTE prv[] = "copy-immutable-privexp";
  static CK_BYTE p1[] = "copy-immutable-p1";
  static CK_BYTE p2[] = "copy-immutable-p2";
  static CK_BYTE e1[] = "copy-immutable-e1";
  static CK_BYTE e2[] = "copy-immutable-e2";
  static CK_BYTE cc[] = "copy-immutable-cc";
  static CK_BYTE kval[16] = { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                              0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };

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

  /* Sealed RSA private, stored sensitive. */
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

  /* Sealed RSA private, stored unextractable. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_MODULUS, mod, sizeof(mod) - 1 },
      { CKA_PUBLIC_EXPONENT, pub, sizeof(pub) - 1 },
      { CKA_PRIVATE_EXPONENT, prv, sizeof(prv) - 1 },
      { CKA_PRIME_1, p1, sizeof(p1) - 1 },
      { CKA_PRIME_2, p2, sizeof(p2) - 1 },
      { CKA_EXPONENT_1, e1, sizeof(e1) - 1 },
      { CKA_EXPONENT_2, e2, sizeof(e2) - 1 },
      { CKA_COEFFICIENT, cc, sizeof(cc) - 1 }
    };
    rv = f->C_CreateObject(sess, t, 13, &unextRsa);
    CHECK(rv == CKR_OK && unextRsa != 0, "unextractable RSA imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Sealed AES, stored sensitive. */
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

  /* Sealed AES, stored unextractable. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_VALUE, kval, sizeof(kval) }
    };
    rv = f->C_CreateObject(sess, t, 6, &unextAes);
    CHECK(rv == CKR_OK && unextAes != 0, "unextractable AES imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Flag-less AES (sealed by the defaults). */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seckls, sizeof(seckls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VALUE, kval, sizeof(kval) }
    };
    rv = f->C_CreateObject(sess, t, 4, &legacyAes);
    CHECK(rv == CKR_OK && legacyAes != 0, "legacy AES imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  if (sensRsa != 0 && unextRsa != 0 && sensAes != 0 && unextAes != 0 &&
      legacyAes != 0) {
    CK_ATTRIBUTE toPub[] = { { CKA_CLASS, &pubcls, sizeof(pubcls) } };
    CK_ATTRIBUTE toData[] = { { CKA_CLASS, &datacls, sizeof(datacls) } };
    CK_ATTRIBUTE toEc[] = { { CKA_KEY_TYPE, &eckt, sizeof(eckt) } };
    CK_ATTRIBUTE toGen[] = { { CKA_KEY_TYPE, &genkt, sizeof(genkt) } };
    check_refused(sess, sensRsa, toPub, 1, "sensitive RSA + CLASS=PUBLIC");
    check_refused(sess, sensRsa, toData, 1, "sensitive RSA + CLASS=DATA");
    check_refused(sess, sensRsa, toEc, 1, "sensitive RSA + changed KEY_TYPE");
    check_refused(sess, unextRsa, toPub, 1, "unextractable RSA + CLASS=PUBLIC");
    check_refused(sess, unextRsa, toData, 1, "unextractable RSA + CLASS=DATA");
    check_refused(sess, unextRsa, toEc, 1, "unextractable RSA + changed KEY_TYPE");
    check_refused(sess, sensAes, toPub, 1, "sensitive AES + CLASS=PUBLIC");
    check_refused(sess, sensAes, toData, 1, "sensitive AES + CLASS=DATA");
    check_refused(sess, sensAes, toGen, 1, "sensitive AES + changed KEY_TYPE");
    check_refused(sess, unextAes, toPub, 1, "unextractable AES + CLASS=PUBLIC");
    check_refused(sess, unextAes, toData, 1, "unextractable AES + CLASS=DATA");
    check_refused(sess, unextAes, toGen, 1, "unextractable AES + changed KEY_TYPE");
    check_refused(sess, legacyAes, toPub, 1, "legacy AES + CLASS=PUBLIC");
    check_refused(sess, legacyAes, toData, 1, "legacy AES + CLASS=DATA");
    check_refused(sess, legacyAes, toGen, 1, "legacy AES + changed KEY_TYPE");

    /* A copy keeping the same class and key type still works. */
    {
      CK_OBJECT_HANDLE h2 = 0;
      CK_OBJECT_CLASS got = 0;
      CK_ATTRIBUTE same[] = {
        { CKA_CLASS, &privcls, sizeof(privcls) },
        { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
        { CKA_LABEL, (CK_VOID_PTR)"rsa-same", 8 }
      };
      CK_ATTRIBUTE q[] = { { CKA_CLASS, &got, sizeof(got) } };
      rv = f->C_CopyObject(sess, sensRsa, same, 3, &h2);
      CHECK(rv == CKR_OK && h2 != 0 && h2 != sensRsa,
            "same class/type RSA copy works (rv=0x%lx)", (unsigned long)rv);
      if (h2 != 0) {
        track(h2);
        rv = f->C_GetAttributeValue(sess, h2, q, 1);
        CHECK(rv == CKR_OK && got == CKO_PRIVATE_KEY &&
              q[0].ulValueLen == sizeof(got),
              "same class/type RSA copy keeps its class (rv=0x%lx)",
              (unsigned long)rv);
      }
    }
    {
      CK_OBJECT_HANDLE h2 = 0;
      CK_OBJECT_CLASS got = 0;
      CK_ATTRIBUTE same[] = {
        { CKA_CLASS, &seckls, sizeof(seckls) },
        { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
        { CKA_LABEL, (CK_VOID_PTR)"aes-same", 8 }
      };
      CK_ATTRIBUTE q[] = { { CKA_CLASS, &got, sizeof(got) } };
      rv = f->C_CopyObject(sess, sensAes, same, 3, &h2);
      CHECK(rv == CKR_OK && h2 != 0 && h2 != sensAes,
            "same class/type AES copy works (rv=0x%lx)", (unsigned long)rv);
      if (h2 != 0) {
        track(h2);
        rv = f->C_GetAttributeValue(sess, h2, q, 1);
        CHECK(rv == CKR_OK && got == CKO_SECRET_KEY &&
              q[0].ulValueLen == sizeof(got),
              "same class/type AES copy keeps its class (rv=0x%lx)",
              (unsigned long)rv);
      }
    }
  }

  for (i = 0; i < g_nleaked; i++) {
    rv = f->C_DestroyObject(sess, g_leaked[i]);
    CHECK(rv == CKR_OK, "copy destroyed");
  }
  if (sensRsa != 0) {
    rv = f->C_DestroyObject(sess, sensRsa);
    CHECK(rv == CKR_OK, "sensitive RSA destroyed");
  }
  if (unextRsa != 0) {
    rv = f->C_DestroyObject(sess, unextRsa);
    CHECK(rv == CKR_OK, "unextractable RSA destroyed");
  }
  if (sensAes != 0) {
    rv = f->C_DestroyObject(sess, sensAes);
    CHECK(rv == CKR_OK, "sensitive AES destroyed");
  }
  if (unextAes != 0) {
    rv = f->C_DestroyObject(sess, unextAes);
    CHECK(rv == CKR_OK, "unextractable AES destroyed");
  }
  if (legacyAes != 0) {
    rv = f->C_DestroyObject(sess, legacyAes);
    CHECK(rv == CKR_OK, "legacy AES destroyed");
  }

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_copy_immutable (copy refuses class/type rewrites)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
