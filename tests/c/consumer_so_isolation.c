/* tests/c/consumer_so_isolation.c — F-1 (FINAL-20): SO/user private-object
 * isolation at the C ABI surface.
 *
 * An SO session must not see or use user CKA_PRIVATE=true objects:
 *   - SO C_FindObjects over a slot holding a user private key yields zero
 *     handles (base: yields the key — the demonstrated vulnerability);
 *   - SO read (C_GetAttributeValue) and use (C_SignInit) are asserted
 *     unconditionally — against the discovered handle when find leaks
 *     one (base), else against the retained user handle — and must
 *     refuse with CKR_OBJECT_HANDLE_INVALID;
 *   - a sign operation initialized before logout must not survive it:
 *     SO C_Sign after the transition refuses with
 *     CKR_OPERATION_NOT_INITIALIZED (cached-operation bypass pin);
 *   - user-session outputs (find count, label readback, HMAC-SHA256 over
 *     fixed bytes) print deterministically so base-vs-patch runs diff
 *     byte-identical (behavior preservation);
 *   - a user re-login after the SO leg re-finds the key (login-transition
 *     regression).
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_so_isolation <path-to-libhaskoki.so>
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

static void hex_of(const CK_BYTE *b, CK_ULONG n, char *out) {
  static const char *d = "0123456789abcdef";
  CK_ULONG i;
  for (i = 0; i < n; i++) {
    out[2 * i] = d[(b[i] >> 4) & 0xf];
    out[2 * i + 1] = d[b[i] & 0xf];
  }
  out[2 * n] = '\0';
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_FUNCTION_LIST_PTR f = NULL;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE userKey = 0;
  CK_BYTE keyBytes[32];
  CK_ULONG i;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  for (i = 0; i < sizeof(keyBytes); i++) {
    keyBytes[i] = (CK_BYTE)(0x10 + i);
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
  rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots >= 1, "token slot present");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok");

  /* ---- user leg: create + use the private key (deterministic prints) ---- */
  {
    CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype = CKK_GENERIC_SECRET;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
      { CKA_CLASS, &klass, sizeof(klass) },
      { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
      { CKA_VALUE, keyBytes, sizeof(keyBytes) },
      { CKA_TOKEN, &yes, sizeof(yes) },
      { CKA_PRIVATE, &yes, sizeof(yes) },
      { CKA_SIGN, &yes, sizeof(yes) },
      { CKA_LABEL, "f1-so-key", 9 },
    };
    CK_ATTRIBUTE match[] = { { CKA_LABEL, "f1-so-key", 9 } };
    CK_OBJECT_HANDLE found[4];
    CK_ULONG nfound = 4;
    CK_BYTE label[32];
    CK_ATTRIBUTE get[] = { { CKA_LABEL, label, sizeof(label) } };
    CK_MECHANISM hm = { CKM_SHA256_HMAC, NULL_PTR, 0 };
    CK_BYTE sig[64];
    CK_ULONG sigLen = sizeof(sig);
    char sigHex[129];

    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECK(rv == CKR_OK, "user login ok");
    rv = f->C_CreateObject(sess, tmpl, 7, &userKey);
    CHECK(rv == CKR_OK && userKey != 0, "private token key created");
    rv = f->C_FindObjectsInit(sess, match, 1);
    CHECK(rv == CKR_OK, "user find init ok");
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECK(rv == CKR_OK && nfound == 1, "user find yields the key");
    rv = f->C_FindObjectsFinal(sess);
    CHECK(rv == CKR_OK, "user find final ok");
    printf("user: find=%lu\n", (unsigned long)nfound);
    rv = f->C_GetAttributeValue(sess, userKey, get, 1);
    CHECK(rv == CKR_OK && get[0].ulValueLen == 9 &&
              memcmp(label, "f1-so-key", 9) == 0,
          "user reads key label");
    printf("user: label=%.*s\n", (int)get[0].ulValueLen, (char *)label);
    rv = f->C_SignInit(sess, &hm, userKey);
    CHECK(rv == CKR_OK, "user SignInit ok");
    rv = f->C_Sign(sess, (CK_BYTE_PTR) "f1-bytes", 8, sig, &sigLen);
    CHECK(rv == CKR_OK && sigLen == 32, "user sign yields 32 bytes");
    hex_of(sig, sigLen, sigHex);
    printf("user: sign=OK siglen=%lu sig=%s\n", (unsigned long)sigLen, sigHex);
    /* Leave a second sign initialized: logout must retire it, so the
     * SO leg's C_Sign cannot drive init-before-logout key use. No
     * print here: the user: lines stay byte-identical. */
    rv = f->C_SignInit(sess, &hm, userKey);
    CHECK(rv == CKR_OK, "user second SignInit ok");
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "user logout ok");
  }

  /* ---- SO leg: the isolation assertions (F-1 fails on base) ---- */
  {
    CK_ATTRIBUTE match[] = { { CKA_LABEL, "f1-so-key", 9 } };
    CK_OBJECT_HANDLE found[4] = { 0, 0, 0, 0 };
    CK_ULONG nfound = 4;

    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
    CHECK(rv == CKR_OK, "SO login ok");
    rv = f->C_FindObjectsInit(sess, match, 1);
    CHECK(rv == CKR_OK, "SO find init ok");
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECK(rv == CKR_OK, "SO find call ok");
    rv = f->C_FindObjectsFinal(sess);
    CHECK(rv == CKR_OK, "SO find final ok");
    printf("so: find=%lu\n", (unsigned long)nfound);
    CHECK(nfound == 0, "SO must not see the user private key");
    {
      /* Read/use refusal is asserted unconditionally: against the
       * leaked handle when find exposes one (base), else against
       * the retained user handle (stale after logout, invisible
       * under SO either way). Both must refuse with
       * CKR_OBJECT_HANDLE_INVALID. */
      CK_OBJECT_HANDLE target = (nfound > 0) ? found[0] : userKey;
      CK_BYTE label[32];
      CK_ATTRIBUTE get[] = { { CKA_LABEL, label, sizeof(label) } };
      CK_MECHANISM hm = { CKM_SHA256_HMAC, NULL_PTR, 0 };
      CK_BYTE sig[64];
      CK_ULONG sigLen = sizeof(sig);

      rv = f->C_GetAttributeValue(sess, target, get, 1);
      printf("so: read rv=0x%lx\n", (unsigned long)rv);
      CHECK(rv == CKR_OBJECT_HANDLE_INVALID,
            "SO read refused with OBJECT_HANDLE_INVALID");
      rv = f->C_SignInit(sess, &hm, target);
      printf("so: signinit rv=0x%lx\n", (unsigned long)rv);
      CHECK(rv == CKR_OBJECT_HANDLE_INVALID,
            "SO sign-init refused with OBJECT_HANDLE_INVALID");
      /* The user leg left a sign initialized before logout: logout
       * must have retired it, so this C_Sign has no operation. */
      sigLen = sizeof(sig);
      rv = f->C_Sign(sess, (CK_BYTE_PTR) "f1-bytes", 8, sig, &sigLen);
      printf("so: signafterlogout rv=0x%lx\n", (unsigned long)rv);
      CHECK(rv == CKR_OPERATION_NOT_INITIALIZED,
            "SO sign after logout refused with OPERATION_NOT_INITIALIZED");
    }
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "SO logout ok");
  }

  /* ---- transition leg: user re-login re-finds the key ---- */
  {
    CK_ATTRIBUTE match[] = { { CKA_LABEL, "f1-so-key", 9 } };
    CK_OBJECT_HANDLE found[4];
    CK_ULONG nfound = 4;

    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECK(rv == CKR_OK, "user re-login ok");
    rv = f->C_FindObjectsInit(sess, match, 1);
    CHECK(rv == CKR_OK, "re-find init ok");
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECK(rv == CKR_OK && nfound == 1, "re-find yields the key again");
    rv = f->C_FindObjectsFinal(sess);
    CHECK(rv == CKR_OK, "re-find final ok");
    printf("user: refind=%lu\n", (unsigned long)nfound);
    if (nfound == 1) {
      rv = f->C_DestroyObject(sess, found[0]);
      CHECK(rv == CKR_OK, "cleanup destroy ok");
    }
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "final logout ok");
  }

  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_so_isolation (SO/user private-object isolation)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
