/* tests/c/consumer_class_confusion.c — asymmetric key types refuse
 * on secret-class objects.
 *
 * A CKO_SECRET_KEY object carrying an asymmetric CKA_KEY_TYPE is
 * incoherent: creation and unwrapping refuse it with
 * CKR_TEMPLATE_INCONSISTENT, so no confused object can exist to
 * reach the crypto paths. Coherent objects (secret AES created
 * and unwrapped, an RSA pair generated and signing) keep working.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_class_confusion <path-to-libhaskoki.so>
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
static CK_OBJECT_CLASS seccls = CKO_SECRET_KEY;
static CK_KEY_TYPE aeskt = CKK_AES;

static CK_ULONG count_label(CK_SESSION_HANDLE s, const char *label) {
  CK_ATTRIBUTE match[] = {
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) }
  };
  CK_OBJECT_HANDLE found[8];
  CK_ULONG n = 0;
  CK_RV rv = f->C_FindObjectsInit(s, match, 1);
  CHECK(rv == CKR_OK, "find init %s", label);
  if (rv != CKR_OK) {
    return 999;
  }
  rv = f->C_FindObjects(s, found, 8, &n);
  CHECK(rv == CKR_OK, "find %s", label);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "find final %s", label);
  return n;
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE wrap = 0, target = 0, aesH = 0, unwrapped = 0;
  CK_OBJECT_HANDLE rsaPub = 0, rsaPriv = 0;
  CK_BYTE val[16], wkey[32];
  CK_BYTE blob[64];
  CK_ULONG blobLen = sizeof(blob);
  CK_ULONG i;
  CK_MECHANISM kw, signMech;
  CK_BYTE msg[] = "class-confusion probe";
  CK_BYTE sig[512];
  CK_ULONG sigLen = sizeof(sig);

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

  for (i = 0; i < sizeof(val); i++) {
    val[i] = (CK_BYTE)(0x40 + i);
  }
  for (i = 0; i < sizeof(wkey); i++) {
    wkey[i] = (CK_BYTE)(0x60 + i);
  }

  /* Creation refuses an asymmetric type on a secret object. */
  {
    static const CK_KEY_TYPE bad[] = {
      CKK_RSA, CKK_EC, CKK_DSA, CKK_DH, CKK_EC_EDWARDS,
      CKK_EC_MONTGOMERY, CKK_ML_KEM, CKK_ML_DSA, CKK_SLH_DSA
    };
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      CK_KEY_TYPE kt = bad[i];
      CK_OBJECT_HANDLE h = 0;
      CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_LABEL, (CK_VOID_PTR)"confused", 8 },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_VALUE, val, sizeof(val) }
      };
      rv = f->C_CreateObject(sess, t, 6, &h);
      CHECK(rv == CKR_TEMPLATE_INCONSISTENT && h == 0,
            "secret create with type 0x%lx refuses (rv=0x%lx)",
            (unsigned long)kt, (unsigned long)rv);
      if (rv == CKR_TEMPLATE_INCONSISTENT) {
        printf("class-confusion: create secret/0x%lx refused 0x%lx\n",
               (unsigned long)kt, (unsigned long)rv);
      }
    }
    CHECK(count_label(sess, "confused") == 0,
          "refused creates publish no object");
  }

  /* A coherent secret still imports. */
  {
    CK_OBJECT_HANDLE h = 0;
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_LABEL, (CK_VOID_PTR)"plain-aes", 9 },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_VALUE, val, sizeof(val) }
    };
    rv = f->C_CreateObject(sess, t, 7, &h);
    CHECK(rv == CKR_OK && h != 0, "secret AES imports (rv=0x%lx)",
          (unsigned long)rv);
    aesH = h;
  }

  /* Wrap one AES key under AES-KW for the unwrap legs. */
  {
    CK_ATTRIBUTE wt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_WRAP, &bTrue, sizeof(bTrue) },
      { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
      { CKA_VALUE, wkey, sizeof(wkey) }
    };
    CK_ATTRIBUTE tt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_VALUE, val, sizeof(val) }
    };
    rv = f->C_CreateObject(sess, wt, 7, &wrap);
    CHECK(rv == CKR_OK && wrap != 0, "wrapping key imports (rv=0x%lx)",
          (unsigned long)rv);
    rv = f->C_CreateObject(sess, tt, 6, &target);
    CHECK(rv == CKR_OK && target != 0, "wrap target imports (rv=0x%lx)",
          (unsigned long)rv);
    kw.mechanism = CKM_AES_KEY_WRAP;
    kw.pParameter = NULL_PTR;
    kw.ulParameterLen = 0;
    rv = f->C_WrapKey(sess, &kw, wrap, target, blob, &blobLen);
    CHECK(rv == CKR_OK && blobLen == 24, "wrap yields 24 bytes (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* Unwrap refuses an asymmetric type on a secret template. */
  {
    static const CK_KEY_TYPE bad[] = { CKK_RSA, CKK_EC, CKK_ML_KEM };
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      CK_KEY_TYPE kt = bad[i];
      CK_OBJECT_HANDLE h = 0;
      CK_ATTRIBUTE t[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_LABEL, (CK_VOID_PTR)"confused", 8 },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
      };
      rv = f->C_UnwrapKey(sess, &kw, wrap, blob, blobLen, t, 4, &h);
      CHECK(rv == CKR_TEMPLATE_INCONSISTENT && h == 0,
            "secret unwrap with type 0x%lx refuses (rv=0x%lx)",
            (unsigned long)kt, (unsigned long)rv);
      if (rv == CKR_TEMPLATE_INCONSISTENT) {
        printf("class-confusion: unwrap secret/0x%lx refused 0x%lx\n",
               (unsigned long)kt, (unsigned long)rv);
      }
    }
    CHECK(count_label(sess, "confused") == 0,
          "refused unwraps publish no object");
  }

  /* A coherent unwrap still lands a usable AES key. */
  {
    CK_OBJECT_HANDLE h = 0;
    CK_MECHANISM ecb;
    CK_BYTE ct[32];
    CK_ULONG ctLen = sizeof(ct);
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_LABEL, (CK_VOID_PTR)"unwrapped-aes", 13 },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) }
    };
    rv = f->C_UnwrapKey(sess, &kw, wrap, blob, blobLen, t, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "secret AES unwraps (rv=0x%lx)",
          (unsigned long)rv);
    unwrapped = h;
    if (rv == CKR_OK && h != 0) {
      ecb.mechanism = CKM_AES_ECB;
      ecb.pParameter = NULL_PTR;
      ecb.ulParameterLen = 0;
      rv = f->C_EncryptInit(sess, &ecb, h);
      CHECK(rv == CKR_OK, "unwrapped key encrypts (rv=0x%lx)",
            (unsigned long)rv);
      if (rv == CKR_OK) {
        memset(ct, 0, sizeof(ct));
        rv = f->C_Encrypt(sess, val, 16, ct, &ctLen);
        CHECK(rv == CKR_OK && ctLen == 16, "unwrap KAT shape (rv=0x%lx)",
              (unsigned long)rv);
      }
    }
  }

  /* Coherent asymmetric objects still generate and sign. */
  {
    CK_MECHANISM gen;
    CK_ULONG bits = 2048;
    CK_BYTE e[3] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pub[] = {
      { CKA_MODULUS_BITS, &bits, sizeof(bits) },
      { CKA_PUBLIC_EXPONENT, e, sizeof(e) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE priv[] = {
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    gen.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pub, 4, priv, 4, &rsaPub, &rsaPriv);
    CHECK(rv == CKR_OK && rsaPub != 0 && rsaPriv != 0,
          "RSA pair generates (rv=0x%lx)", (unsigned long)rv);
    if (rv == CKR_OK && rsaPub != 0 && rsaPriv != 0) {
      signMech.mechanism = CKM_SHA256_RSA_PKCS;
      signMech.pParameter = NULL_PTR;
      signMech.ulParameterLen = 0;
      rv = f->C_SignInit(sess, &signMech, rsaPriv);
      CHECK(rv == CKR_OK, "RSA SignInit (rv=0x%lx)", (unsigned long)rv);
      if (rv == CKR_OK) {
        rv = f->C_Sign(sess, msg, sizeof(msg) - 1, sig, &sigLen);
        CHECK(rv == CKR_OK && sigLen == 256, "RSA signs 256 (rv=0x%lx)",
              (unsigned long)rv);
      }
      rv = f->C_VerifyInit(sess, &signMech, rsaPub);
      CHECK(rv == CKR_OK, "RSA VerifyInit (rv=0x%lx)", (unsigned long)rv);
      if (rv == CKR_OK) {
        rv = f->C_Verify(sess, msg, sizeof(msg) - 1, sig, sigLen);
        CHECK(rv == CKR_OK, "RSA verifies (rv=0x%lx)", (unsigned long)rv);
      }
    }
  }

  if (aesH != 0) {
    rv = f->C_DestroyObject(sess, aesH);
    CHECK(rv == CKR_OK, "aes destroyed");
  }
  if (wrap != 0) {
    rv = f->C_DestroyObject(sess, wrap);
    CHECK(rv == CKR_OK, "wrap key destroyed");
  }
  if (target != 0) {
    rv = f->C_DestroyObject(sess, target);
    CHECK(rv == CKR_OK, "target destroyed");
  }
  if (unwrapped != 0) {
    rv = f->C_DestroyObject(sess, unwrapped);
    CHECK(rv == CKR_OK, "unwrapped destroyed");
  }
  if (rsaPub != 0) {
    rv = f->C_DestroyObject(sess, rsaPub);
    CHECK(rv == CKR_OK, "rsa pub destroyed");
  }
  if (rsaPriv != 0) {
    rv = f->C_DestroyObject(sess, rsaPriv);
    CHECK(rv == CKR_OK, "rsa priv destroyed");
  }

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_class_confusion (secret/asymmetric coherence)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
