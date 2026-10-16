/* tests/c/consumer_find_sealed.c — sealed private components never match find.
 *
 * A sealed RSA private key (explicitly sensitive, or legacy flag-less)
 * withholds every private component in C_FindObjects, not only CKA_VALUE:
 * a guessed CKA_PRIVATE_EXPONENT, CKA_PRIME_1 or CKA_COEFFICIENT matches
 * nothing, while the public CKA_MODULUS still matches and the object stays
 * discoverable by label. An unsealed control still matches its exponent.
 * Reads agree: sealed exponents refuse CKR_ATTRIBUTE_SENSITIVE.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_find_sealed <path-to-libhaskoki.so>
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

static CK_ULONG count_matches(CK_SESSION_HANDLE s, CK_ATTRIBUTE *tmpl,
                              CK_ULONG ntmpl, const char *what) {
  CK_OBJECT_HANDLE found[8];
  CK_ULONG n = 0;
  CK_RV rv = f->C_FindObjectsInit(s, tmpl, ntmpl);
  CHECK(rv == CKR_OK, "find init %s (rv=0x%lx)", what, (unsigned long)rv);
  if (rv != CKR_OK) {
    return 999;
  }
  rv = f->C_FindObjects(s, found, 8, &n);
  CHECK(rv == CKR_OK, "find %s (rv=0x%lx)", what, (unsigned long)rv);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "find final %s (rv=0x%lx)", what, (unsigned long)rv);
  return n;
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_CLASS privcls = CKO_PRIVATE_KEY;
  CK_KEY_TYPE rsakt = CKK_RSA;
  CK_OBJECT_HANDLE sealedH = 0, legacyH = 0, openH = 0;

  /* Distinct small components per object (unique exponents). */
  static CK_BYTE sMod[] = "sealed-modulus";
  static CK_BYTE sExp[] = "sealed-pubexp";
  static CK_BYTE sPriv[] = "sealed-privexp-guess";
  static CK_BYTE sP1[] = "sealed-prime1";
  static CK_BYTE sP2[] = "sealed-prime2";
  static CK_BYTE sE1[] = "sealed-exp1";
  static CK_BYTE sE2[] = "sealed-exp2";
  static CK_BYTE sC[] = "sealed-coeff";
  static CK_BYTE lMod[] = "legacy-modulus";
  static CK_BYTE lExp[] = "legacy-pubexp";
  static CK_BYTE lPriv[] = "legacy-privexp-guess";
  static CK_BYTE lP1[] = "legacy-prime1";
  static CK_BYTE lP2[] = "legacy-prime2";
  static CK_BYTE lE1[] = "legacy-exp1";
  static CK_BYTE lE2[] = "legacy-exp2";
  static CK_BYTE lC[] = "legacy-coeff";
  static CK_BYTE oMod[] = "open-modulus";
  static CK_BYTE oExp[] = "open-pubexp";
  static CK_BYTE oPriv[] = "open-privexp-guess";
  static CK_BYTE oP1[] = "open-prime1";
  static CK_BYTE oP2[] = "open-prime2";
  static CK_BYTE oE1[] = "open-exp1";
  static CK_BYTE oE2[] = "open-exp2";
  static CK_BYTE oC[] = "open-coeff";

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

  /* Explicitly sealed RSA private. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"sealed-rsa", 10 },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_MODULUS, sMod, sizeof(sMod) - 1 },
      { CKA_PUBLIC_EXPONENT, sExp, sizeof(sExp) - 1 },
      { CKA_PRIVATE_EXPONENT, sPriv, sizeof(sPriv) - 1 },
      { CKA_PRIME_1, sP1, sizeof(sP1) - 1 },
      { CKA_PRIME_2, sP2, sizeof(sP2) - 1 },
      { CKA_EXPONENT_1, sE1, sizeof(sE1) - 1 },
      { CKA_EXPONENT_2, sE2, sizeof(sE2) - 1 },
      { CKA_COEFFICIENT, sC, sizeof(sC) - 1 }
    };
    rv = f->C_CreateObject(sess, t, 14, &sealedH);
    CHECK(rv == CKR_OK && sealedH != 0, "sealed RSA private imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Legacy flag-less RSA private (no protection flags stored). */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"legacy-rsa", 10 },
      { CKA_MODULUS, lMod, sizeof(lMod) - 1 },
      { CKA_PUBLIC_EXPONENT, lExp, sizeof(lExp) - 1 },
      { CKA_PRIVATE_EXPONENT, lPriv, sizeof(lPriv) - 1 },
      { CKA_PRIME_1, lP1, sizeof(lP1) - 1 },
      { CKA_PRIME_2, lP2, sizeof(lP2) - 1 },
      { CKA_EXPONENT_1, lE1, sizeof(lE1) - 1 },
      { CKA_EXPONENT_2, lE2, sizeof(lE2) - 1 },
      { CKA_COEFFICIENT, lC, sizeof(lC) - 1 }
    };
    rv = f->C_CreateObject(sess, t, 12, &legacyH);
    CHECK(rv == CKR_OK && legacyH != 0, "legacy RSA private imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Unsealed control. */
  {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"open-rsa", 8 },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_MODULUS, oMod, sizeof(oMod) - 1 },
      { CKA_PUBLIC_EXPONENT, oExp, sizeof(oExp) - 1 },
      { CKA_PRIVATE_EXPONENT, oPriv, sizeof(oPriv) - 1 },
      { CKA_PRIME_1, oP1, sizeof(oP1) - 1 },
      { CKA_PRIME_2, oP2, sizeof(oP2) - 1 },
      { CKA_EXPONENT_1, oE1, sizeof(oE1) - 1 },
      { CKA_EXPONENT_2, oE2, sizeof(oE2) - 1 },
      { CKA_COEFFICIENT, oC, sizeof(oC) - 1 }
    };
    rv = f->C_CreateObject(sess, t, 14, &openH);
    CHECK(rv == CKR_OK && openH != 0, "open RSA private imports (rv=0x%lx)",
          (unsigned long)rv);
  }

  if (sealedH != 0 && legacyH != 0 && openH != 0) {
    /* Guessed sealed exponents match nothing. */
    {
      CK_ATTRIBUTE q[] = {
        { CKA_PRIVATE_EXPONENT, sPriv, sizeof(sPriv) - 1 }
      };
      CHECK(count_matches(sess, q, 1, "sealed exponent") == 0,
            "sealed exponent guess matches nothing");
    }
    {
      CK_ATTRIBUTE q[] = {
        { CKA_PRIVATE_EXPONENT, lPriv, sizeof(lPriv) - 1 }
      };
      CHECK(count_matches(sess, q, 1, "legacy exponent") == 0,
            "legacy exponent guess matches nothing");
    }
    /* Other sealed components match nothing either. */
    {
      CK_ATTRIBUTE q[] = { { CKA_PRIME_1, sP1, sizeof(sP1) - 1 } };
      CHECK(count_matches(sess, q, 1, "sealed prime") == 0,
            "sealed prime guess matches nothing");
    }
    {
      CK_ATTRIBUTE q[] = { { CKA_COEFFICIENT, lC, sizeof(lC) - 1 } };
      CHECK(count_matches(sess, q, 1, "legacy coeff") == 0,
            "legacy coefficient guess matches nothing");
    }
    /* Public modulus still matches; sealed objects stay discoverable. */
    {
      CK_ATTRIBUTE q[] = { { CKA_MODULUS, sMod, sizeof(sMod) - 1 } };
      CHECK(count_matches(sess, q, 1, "sealed modulus") == 1,
            "sealed modulus still matches");
    }
    {
      CK_ATTRIBUTE q[] = {
        { CKA_LABEL, (CK_VOID_PTR)"sealed-rsa", 10 }
      };
      CHECK(count_matches(sess, q, 1, "sealed label") == 1,
            "sealed object found by label");
    }
    {
      CK_ATTRIBUTE q[] = {
        { CKA_LABEL, (CK_VOID_PTR)"legacy-rsa", 10 }
      };
      CHECK(count_matches(sess, q, 1, "legacy label") == 1,
            "legacy object found by label");
    }
    /* Unsealed control still matches its exponent. */
    {
      CK_ATTRIBUTE q[] = {
        { CKA_PRIVATE_EXPONENT, oPriv, sizeof(oPriv) - 1 }
      };
      CHECK(count_matches(sess, q, 1, "open exponent") == 1,
            "open exponent still matches");
    }
    /* Reads agree: sealed exponents refuse sensitive, open reads. */
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE q[] = { { CKA_PRIVATE_EXPONENT, buf, sizeof(buf) } };
      rv = f->C_GetAttributeValue(sess, sealedH, q, 1);
      CHECK(rv == CKR_ATTRIBUTE_SENSITIVE,
            "sealed exponent read refused (rv=0x%lx)", (unsigned long)rv);
    }
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE q[] = { { CKA_PRIVATE_EXPONENT, buf, sizeof(buf) } };
      rv = f->C_GetAttributeValue(sess, legacyH, q, 1);
      CHECK(rv == CKR_ATTRIBUTE_SENSITIVE,
            "legacy exponent read refused (rv=0x%lx)", (unsigned long)rv);
    }
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE q[] = { { CKA_PRIVATE_EXPONENT, buf, sizeof(buf) } };
      memset(buf, 0, sizeof(buf));
      q[0].ulValueLen = sizeof(buf);
      rv = f->C_GetAttributeValue(sess, openH, q, 1);
      CHECK(rv == CKR_OK && q[0].ulValueLen == sizeof(oPriv) - 1 &&
            memcmp(buf, oPriv, sizeof(oPriv) - 1) == 0,
            "open exponent reads back (rv=0x%lx)", (unsigned long)rv);
    }
  }

  if (sealedH != 0) {
    rv = f->C_DestroyObject(sess, sealedH);
    CHECK(rv == CKR_OK, "sealed destroyed");
  }
  if (legacyH != 0) {
    rv = f->C_DestroyObject(sess, legacyH);
    CHECK(rv == CKR_OK, "legacy destroyed");
  }
  if (openH != 0) {
    rv = f->C_DestroyObject(sess, openH);
    CHECK(rv == CKR_OK, "open destroyed");
  }

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_find_sealed (sealed find withholds)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
