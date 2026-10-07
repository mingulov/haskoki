/* tests/c/consumer_derive_f10.c — F-10 (FINAL-15): per-row public-C
 * parity for the five wired derive advertisements.
 *
 * Each of CKM_PKCS5_PBKD2, CKM_DES_ECB/CBC_ENCRYPT_DATA and
 * CKM_SEED_ECB/CBC_ENCRYPT_DATA must be BOTH advertised
 * (C_GetMechanismInfo carries CKF_DERIVE) AND served
 * (C_DeriveKey returns CKR_OK with a live handle). Base behavior:
 * advertised but refused with CKR_FUNCTION_NOT_SUPPORTED.
 *
 * Correctness pins (public surface, no provider internals):
 *   - PBKD2 derive (password rides a generic-secret base key,
 *     empty struct password) matches the RFC 6070 c=1 vector
 *     byte-for-byte, and matches the PBKD2 keygen route for the
 *     same password/salt/iterations;
 *   - every encrypt-data derive equals a one-shot C_Encrypt of
 *     the same data under the same base key (and IV for CBC);
 *   - malformed frames refuse typed and write no handle
 *     (ragged data -> CKR_MECHANISM_PARAM_INVALID; PBKD2 with a
 *     non-empty struct password or an unmapped PRF ->
 *     CKR_ARGUMENTS_BAD, the planner's pre-existing code);
 *   - served-row vectors (AES-CBC-ENCRYPT_DATA, PBKD2 keygen)
 *     print deterministically and are pinned to their pre-patch
 *     values (behavior preservation).
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_derive_f10 <path-to-libhaskoki.so>
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

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

static CK_OBJECT_HANDLE mkbase(CK_SESSION_HANDLE s, CK_KEY_TYPE kt,
                               CK_BYTE *val, CK_ULONG vlen) {
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_VALUE, val, vlen },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_DERIVE, &bTrue, sizeof(bTrue) },
    { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
    { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) }
  };
  CK_OBJECT_HANDLE h = 0;
  CK_RV rv = f->C_CreateObject(s, t, 9, &h);
  CHECK(rv == CKR_OK && h != 0, "base imports (kt=0x%lx rv=0x%lx)",
        (unsigned long)kt, (unsigned long)rv);
  return h;
}

/* Derive one generic-secret object; returns CKR_OK with *ph and *gotLen set. */
static CK_RV derive_one(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                        CK_OBJECT_HANDLE base, CK_ULONG outlen,
                        CK_OBJECT_HANDLE *ph, CK_BYTE *got, CK_ULONG gotCap,
                        CK_ULONG *gotLen) {
  CK_OBJECT_CLASS dcls = CKO_SECRET_KEY;
  CK_KEY_TYPE dkt = CKK_GENERIC_SECRET;
  CK_ATTRIBUTE dt[] = {
    { CKA_CLASS, &dcls, sizeof(dcls) },
    { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
    { CKA_VALUE_LEN, &outlen, sizeof(outlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) }
  };
  CK_ATTRIBUTE g[] = { { CKA_VALUE, got, gotCap } };
  CK_RV rv;
  memset(got, 0, gotCap);
  *gotLen = 0;
  *ph = 0;
  rv = f->C_DeriveKey(s, m, base, dt, 6, ph);
  if (rv != CKR_OK) {
    return rv;
  }
  g[0].ulValueLen = gotCap;
  rv = f->C_GetAttributeValue(s, *ph, g, 1);
  if (rv != CKR_OK) {
    return rv;
  }
  *gotLen = g[0].ulValueLen;
  return CKR_OK;
}

static void check_advertised(CK_MECHANISM_TYPE mech, const char *name) {
  CK_MECHANISM_INFO mi;
  CK_RV rv = f->C_GetMechanismInfo(0, mech, &mi);
  CHECK(rv == CKR_OK, "%s mechanism info ok", name);
  CHECK(rv == CKR_OK && (mi.flags & CKF_DERIVE) != 0,
        "%s advertises CKF_DERIVE (flags=0x%lx)", name,
        rv == CKR_OK ? (unsigned long)mi.flags : 0UL);
}

/* One-shot encrypt for the derive==encrypt cross-check. */
static CK_RV encrypt_one(CK_SESSION_HANDLE s, CK_MECHANISM_TYPE mech,
                         CK_BYTE *iv, CK_ULONG ivLen, CK_OBJECT_HANDLE key,
                         CK_BYTE *pt, CK_ULONG ptLen,
                         CK_BYTE *ct, CK_ULONG *ctLen) {
  CK_MECHANISM m;
  CK_RV rv;
  m.mechanism = mech;
  m.pParameter = iv;
  m.ulParameterLen = ivLen;
  rv = f->C_EncryptInit(s, &m, key);
  if (rv != CKR_OK) {
    return rv;
  }
  return f->C_Encrypt(s, pt, ptLen, ct, ctLen);
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE hdes = 0, hseed = 0, hpwd = 0, haes = 0;
  CK_BYTE deskey[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  CK_BYTE seedkey[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  CK_BYTE pwd[] = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
  CK_BYTE aeskey[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };

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

  hdes = mkbase(sess, CKK_DES, deskey, sizeof(deskey));
  hseed = mkbase(sess, CKK_SEED, seedkey, sizeof(seedkey));
  hpwd = mkbase(sess, CKK_GENERIC_SECRET, pwd, sizeof(pwd));
  haes = mkbase(sess, CKK_AES, aeskey, sizeof(aeskey));

  /* ---- row 1: DES-CBC-ENCRYPT_DATA (+ ragged-data refusal) ---- */
  {
    CK_DES_CBC_ENCRYPT_DATA_PARAMS p;
    CK_MECHANISM m;
    CK_BYTE iv[8] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    CK_BYTE data[8] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03 };
    CK_OBJECT_HANDLE dh = 0;
    CK_BYTE got[8], ct[16];
    CK_ULONG gotLen = 0, ctLen = sizeof(ct);
    char hx[17];
    check_advertised(CKM_DES_CBC_ENCRYPT_DATA, "CKM_DES_CBC_ENCRYPT_DATA");
    memcpy(p.iv, iv, sizeof(iv));
    p.pData = data;
    p.length = sizeof(data);
    m.mechanism = CKM_DES_CBC_ENCRYPT_DATA;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = derive_one(sess, &m, hdes, 8, &dh, got, sizeof(got), &gotLen);
    CHECK(rv == CKR_OK && dh != 0 && gotLen == 8,
          "DES-CBC-ENCRYPT_DATA derives (rv=0x%lx)", (unsigned long)rv);
    rv = encrypt_one(sess, CKM_DES_CBC, iv, sizeof(iv), hdes,
                     data, sizeof(data), ct, &ctLen);
    CHECK(rv == CKR_OK && ctLen == 8 && memcmp(ct, got, 8) == 0,
          "DES-CBC derive == DES-CBC encrypt");
    hex_of(got, 8, hx);
    printf("derive: des_cbc=%s\n", hx);
    p.length = 5;
    {
      CK_OBJECT_HANDLE bad = 0;
      CK_OBJECT_CLASS dcls = CKO_SECRET_KEY;
      CK_KEY_TYPE dkt = CKK_GENERIC_SECRET;
      CK_ULONG ol = 8;
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &dcls, sizeof(dcls) },
        { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
        { CKA_VALUE_LEN, &ol, sizeof(ol) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) }
      };
      rv = f->C_DeriveKey(sess, &m, hdes, dt, 6, &bad);
      CHECK(rv == CKR_MECHANISM_PARAM_INVALID && bad == 0,
            "DES-CBC ragged data refused typed");
    }
  }

  /* ---- row 2 (variant): DES-ECB-ENCRYPT_DATA, same class ---- */
  {
    CK_KEY_DERIVATION_STRING_DATA p;
    CK_MECHANISM m;
    CK_BYTE data[8] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03 };
    CK_OBJECT_HANDLE dh = 0;
    CK_BYTE got[8], ct[16];
    CK_ULONG gotLen = 0, ctLen = sizeof(ct);
    char hx[17];
    check_advertised(CKM_DES_ECB_ENCRYPT_DATA, "CKM_DES_ECB_ENCRYPT_DATA");
    p.pData = data;
    p.ulLen = sizeof(data);
    m.mechanism = CKM_DES_ECB_ENCRYPT_DATA;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = derive_one(sess, &m, hdes, 8, &dh, got, sizeof(got), &gotLen);
    CHECK(rv == CKR_OK && dh != 0 && gotLen == 8,
          "DES-ECB-ENCRYPT_DATA derives (rv=0x%lx)", (unsigned long)rv);
    rv = encrypt_one(sess, CKM_DES_ECB, NULL_PTR, 0, hdes,
                     data, sizeof(data), ct, &ctLen);
    CHECK(rv == CKR_OK && ctLen == 8 && memcmp(ct, got, 8) == 0,
          "DES-ECB derive == DES-ECB encrypt");
    hex_of(got, 8, hx);
    printf("derive: des_ecb=%s\n", hx);
  }

  /* ---- row 3: SEED-CBC-ENCRYPT_DATA ---- */
  {
    CK_SEED_CBC_ENCRYPT_DATA_PARAMS p;
    CK_MECHANISM m;
    CK_BYTE iv[16] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    CK_BYTE data[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    CK_OBJECT_HANDLE dh = 0;
    CK_BYTE got[16], ct[32];
    CK_ULONG gotLen = 0, ctLen = sizeof(ct);
    char hx[33];
    check_advertised(CKM_SEED_CBC_ENCRYPT_DATA, "CKM_SEED_CBC_ENCRYPT_DATA");
    memcpy(p.iv, iv, sizeof(iv));
    p.pData = data;
    p.length = sizeof(data);
    m.mechanism = CKM_SEED_CBC_ENCRYPT_DATA;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = derive_one(sess, &m, hseed, 16, &dh, got, sizeof(got), &gotLen);
    CHECK(rv == CKR_OK && dh != 0 && gotLen == 16,
          "SEED-CBC-ENCRYPT_DATA derives (rv=0x%lx)", (unsigned long)rv);
    rv = encrypt_one(sess, CKM_SEED_CBC, iv, sizeof(iv), hseed,
                     data, sizeof(data), ct, &ctLen);
    CHECK(rv == CKR_OK && ctLen == 16 && memcmp(ct, got, 16) == 0,
          "SEED-CBC derive == SEED-CBC encrypt");
    hex_of(got, 16, hx);
    printf("derive: seed_cbc=%s\n", hx);
  }

  /* ---- row 4 (variant): SEED-ECB-ENCRYPT_DATA, same class ---- */
  {
    CK_KEY_DERIVATION_STRING_DATA p;
    CK_MECHANISM m;
    CK_BYTE data[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    CK_OBJECT_HANDLE dh = 0;
    CK_BYTE got[16], ct[32];
    CK_ULONG gotLen = 0, ctLen = sizeof(ct);
    char hx[33];
    check_advertised(CKM_SEED_ECB_ENCRYPT_DATA, "CKM_SEED_ECB_ENCRYPT_DATA");
    p.pData = data;
    p.ulLen = sizeof(data);
    m.mechanism = CKM_SEED_ECB_ENCRYPT_DATA;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = derive_one(sess, &m, hseed, 16, &dh, got, sizeof(got), &gotLen);
    CHECK(rv == CKR_OK && dh != 0 && gotLen == 16,
          "SEED-ECB-ENCRYPT_DATA derives (rv=0x%lx)", (unsigned long)rv);
    rv = encrypt_one(sess, CKM_SEED_ECB, NULL_PTR, 0, hseed,
                     data, sizeof(data), ct, &ctLen);
    CHECK(rv == CKR_OK && ctLen == 16 && memcmp(ct, got, 16) == 0,
          "SEED-ECB derive == SEED-ECB encrypt");
    hex_of(got, 16, hx);
    printf("derive: seed_ecb=%s\n", hx);
  }

  /* ---- row 5: PBKD2 derive (RFC 6070 c=1) + refusal pins ---- */
  {
    CK_PKCS5_PBKD2_PARAMS2 p;
    CK_MECHANISM m;
    CK_BYTE salt[] = { 's', 'a', 'l', 't' };
    CK_BYTE rfc[20] = {
      0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
      0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
      0x2f, 0xe0, 0x37, 0xa6
    };
    CK_OBJECT_HANDLE dh = 0, dh2 = 0;
    CK_BYTE got[20], got2[20];
    CK_ULONG gotLen = 0, got2Len = 0;
    char hx[41];
    check_advertised(CKM_PKCS5_PBKD2, "CKM_PKCS5_PBKD2");
    p.saltSource = CKZ_SALT_SPECIFIED;
    p.pSaltSourceData = salt;
    p.ulSaltSourceDataLen = sizeof(salt);
    p.iterations = 1;
    p.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
    p.pPrfData = NULL_PTR;
    p.ulPrfDataLen = 0;
    p.pPassword = NULL_PTR;
    p.ulPasswordLen = 0;
    m.mechanism = CKM_PKCS5_PBKD2;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = derive_one(sess, &m, hpwd, 20, &dh, got, sizeof(got), &gotLen);
    CHECK(rv == CKR_OK && dh != 0 && gotLen == 20,
          "PBKD2 derives (rv=0x%lx)", (unsigned long)rv);
    CHECK(gotLen == 20 && memcmp(got, rfc, 20) == 0,
          "PBKD2 derive matches RFC 6070 c=1");
    hex_of(got, 20, hx);
    printf("derive: pbkd2=%s\n", hx);
    rv = derive_one(sess, &m, hpwd, 20, &dh2, got2, sizeof(got2), &got2Len);
    CHECK(rv == CKR_OK && dh2 != 0 && dh2 != dh &&
          got2Len == 20 && memcmp(got, got2, 20) == 0,
          "second PBKD2 derive deterministic, distinct handle");
    /* A non-empty struct password contradicts the derive route
     * (the password rides the base key) and refuses typed. */
    p.pPassword = pwd;
    p.ulPasswordLen = sizeof(pwd);
    {
      CK_OBJECT_HANDLE bad = 0;
      CK_BYTE tmp[20];
      CK_ULONG tmpLen = 0;
      rv = derive_one(sess, &m, hpwd, 20, &bad, tmp, sizeof(tmp), &tmpLen);
      CHECK(rv == CKR_ARGUMENTS_BAD && bad == 0,
            "PBKD2 derive with inline password refused");
    }
    p.pPassword = NULL_PTR;
    p.ulPasswordLen = 0;
    /* An unmapped PRF fails the normalizer; the raw image then
     * fails the planner's PBKD2 recipe check (CKR_ARGUMENTS_BAD —
     * the planner's pre-existing code for this class; the
     * keygen/derive code asymmetry is FINAL-16 scope, deferred). */
    p.prf = CKP_PKCS5_PBKD2_HMAC_GOSTR3411;
    {
      CK_OBJECT_HANDLE bad = 0;
      CK_BYTE tmp[20];
      CK_ULONG tmpLen = 0;
      rv = derive_one(sess, &m, hpwd, 20, &bad, tmp, sizeof(tmp), &tmpLen);
      CHECK(rv == CKR_ARGUMENTS_BAD && bad == 0,
            "PBKD2 derive with GOST PRF refused typed");
    }
  }

  /* ---- behavior preservation: served-row vectors pinned ---- */
  {
    CK_AES_CBC_ENCRYPT_DATA_PARAMS p;
    CK_MECHANISM m;
    CK_BYTE iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    CK_BYTE dd[16] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    CK_BYTE want[16] = {
      0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
      0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
    CK_OBJECT_HANDLE dh = 0;
    CK_BYTE got[16];
    CK_ULONG gotLen = 0;
    memcpy(p.iv, iv, sizeof(iv));
    p.pData = dd;
    p.length = sizeof(dd);
    m.mechanism = CKM_AES_CBC_ENCRYPT_DATA;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = derive_one(sess, &m, haes, 16, &dh, got, sizeof(got), &gotLen);
    CHECK(rv == CKR_OK && gotLen == 16 && memcmp(got, want, 16) == 0,
          "AES-CBC-ENCRYPT_DATA vector unchanged");
  }
  {
    CK_PKCS5_PBKD2_PARAMS2 p;
    CK_MECHANISM m;
    CK_BYTE salt[] = { 's', 'a', 'l', 't' };
    CK_BYTE rfc[20] = {
      0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
      0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
      0x2f, 0xe0, 0x37, 0xa6
    };
    CK_OBJECT_CLASS dcls = CKO_SECRET_KEY;
    CK_KEY_TYPE dkt = CKK_GENERIC_SECRET;
    CK_ULONG kl = 20;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &dcls, sizeof(dcls) },
      { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
      { CKA_VALUE_LEN, &kl, sizeof(kl) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE dh = 0;
    CK_BYTE got[20];
    CK_ATTRIBUTE g[] = { { CKA_VALUE, got, sizeof(got) } };
    p.saltSource = CKZ_SALT_SPECIFIED;
    p.pSaltSourceData = salt;
    p.ulSaltSourceDataLen = sizeof(salt);
    p.iterations = 1;
    p.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
    p.pPrfData = NULL_PTR;
    p.ulPrfDataLen = 0;
    p.pPassword = pwd;
    p.ulPasswordLen = sizeof(pwd);
    m.mechanism = CKM_PKCS5_PBKD2;
    m.pParameter = &p;
    m.ulParameterLen = sizeof(p);
    rv = f->C_GenerateKey(sess, &m, dt, 5, &dh);
    CHECK(rv == CKR_OK && dh != 0, "PBKD2 keygen still ok");
    g[0].ulValueLen = sizeof(got);
    rv = f->C_GetAttributeValue(sess, dh, g, 1);
    CHECK(rv == CKR_OK && g[0].ulValueLen == 20 &&
          memcmp(got, rfc, 20) == 0, "PBKD2 keygen vector unchanged");
  }

  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_derive_f10 (five derive advertisements wired)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
