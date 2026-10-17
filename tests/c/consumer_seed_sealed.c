/* tests/c/consumer_seed_sealed.c — sealed PQC private keys withhold CKA_SEED.
 *
 * An ML-DSA, ML-KEM, or SLH-DSA private key that is sensitive or
 * unextractable (stored flags or flag-less defaults) refuses
 * C_GetAttributeValue(CKA_SEED) with CKR_ATTRIBUTE_SENSITIVE and
 * length CK_UNAVAILABLE_INFORMATION, and a C_FindObjects template
 * holding the true seed value matches nothing on it. An open
 * (extractable, non-sensitive) key of each family reads its seed
 * back, and a find by that seed hits exactly it. The imports use
 * synthetic component bytes (the import checks widths only, as
 * with the synthetic RSA components elsewhere), so every seed is
 * known and the find legs use true values. One generated sealed
 * ML-DSA pair pins the same read refusal through key generation,
 * which stamps the seed itself.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_seed_sealed <path-to-libhaskoki.so>
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

static CK_OBJECT_HANDLE g_all[32];
static int g_nall = 0;

static void track(CK_OBJECT_HANDLE h) {
  if (h != 0 && g_nall < 32) {
    g_all[g_nall++] = h;
  }
}

/* Deterministic distinct filler: byte j of leg tag is (tag + j * 31). */
static void fill_pat(CK_BYTE *p, CK_ULONG n, unsigned tag) {
  CK_ULONG j;
  for (j = 0; j < n; j++) {
    p[j] = (CK_BYTE)(tag + j * 31);
  }
}

/* True when every byte is still the 0xA5 canary. */
static int filled_canary(const CK_BYTE *p, CK_ULONG n) {
  CK_ULONG j;
  for (j = 0; j < n; j++) {
    if (p[j] != 0xA5) {
      return 0;
    }
  }
  return 1;
}

/* Import one PQC private key with a known seed. hasSens/hasExtr
 * select whether the protection flags are stored (legacy legs omit
 * both). Returns 1 on success. */
static int import_priv(CK_SESSION_HANDLE s, CK_KEY_TYPE kkt, CK_ULONG set,
                       CK_BYTE *val, CK_ULONG valLen, CK_BYTE *seed,
                       CK_ULONG seedLen, int hasSens, CK_BBOOL sens,
                       int hasExtr, CK_BBOOL extr, const char *what,
                       CK_OBJECT_HANDLE *out) {
  CK_OBJECT_CLASS scls = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE t[8];
  CK_ULONG n = 0;
  CK_RV rv;
  t[n].type = CKA_CLASS;
  t[n].pValue = &scls;
  t[n].ulValueLen = sizeof(scls);
  n++;
  t[n].type = CKA_KEY_TYPE;
  t[n].pValue = &kkt;
  t[n].ulValueLen = sizeof(kkt);
  n++;
  t[n].type = CKA_TOKEN;
  t[n].pValue = &bFalse;
  t[n].ulValueLen = sizeof(bFalse);
  n++;
  t[n].type = CKA_PARAMETER_SET;
  t[n].pValue = &set;
  t[n].ulValueLen = sizeof(set);
  n++;
  t[n].type = CKA_VALUE;
  t[n].pValue = val;
  t[n].ulValueLen = valLen;
  n++;
  t[n].type = CKA_SEED;
  t[n].pValue = seed;
  t[n].ulValueLen = seedLen;
  n++;
  if (hasSens) {
    t[n].type = CKA_SENSITIVE;
    t[n].pValue = &sens;
    t[n].ulValueLen = sizeof(sens);
    n++;
  }
  if (hasExtr) {
    t[n].type = CKA_EXTRACTABLE;
    t[n].pValue = &extr;
    t[n].ulValueLen = sizeof(extr);
    n++;
  }
  *out = 0;
  rv = f->C_CreateObject(s, t, n, out);
  CHECK(rv == CKR_OK && *out != 0, "%s imports (rv=0x%lx)", what,
        (unsigned long)rv);
  if (rv != CKR_OK || *out == 0) {
    return 0;
  }
  track(*out);
  return 1;
}

static CK_ULONG seed_find(CK_SESSION_HANDLE s, CK_BYTE *seed,
                          CK_ULONG seedLen, CK_OBJECT_HANDLE *found,
                          const char *what) {
  CK_ULONG n = 0;
  CK_ATTRIBUTE q[] = { { CKA_SEED, seed, seedLen } };
  CK_RV rv = f->C_FindObjectsInit(s, q, 1);
  CHECK(rv == CKR_OK, "seed find init %s (rv=0x%lx)", what, (unsigned long)rv);
  if (rv != CKR_OK) {
    return 999;
  }
  rv = f->C_FindObjects(s, found, 8, &n);
  CHECK(rv == CKR_OK, "seed find %s (rv=0x%lx)", what, (unsigned long)rv);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "seed find final %s (rv=0x%lx)", what, (unsigned long)rv);
  return n;
}

static void check_sealed(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE priv,
                         CK_BYTE *seed, CK_ULONG seedLen, const char *what) {
  CK_BYTE buf[128];
  CK_OBJECT_HANDLE found[8];
  CK_ATTRIBUTE q[] = { { CKA_SEED, buf, sizeof(buf) } };
  CK_RV rv;
  memset(buf, 0xA5, sizeof(buf));
  q[0].ulValueLen = sizeof(buf);
  rv = f->C_GetAttributeValue(s, priv, q, 1);
  CHECK(rv == CKR_ATTRIBUTE_SENSITIVE, "%s seed read refused (rv=0x%lx)",
        what, (unsigned long)rv);
  CHECK(q[0].ulValueLen == CK_UNAVAILABLE_INFORMATION,
        "%s seed length unavailable (len=0x%lx)", what,
        (unsigned long)q[0].ulValueLen);
  CHECK(filled_canary(buf, sizeof(buf)), "%s seed buffer untouched", what);
  CHECK(seed_find(s, seed, seedLen, found, what) == 0,
        "%s find by true seed matches nothing", what);
}

static void check_open(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE priv,
                       CK_BYTE *seed, CK_ULONG seedLen, const char *what) {
  CK_BYTE buf[128];
  CK_OBJECT_HANDLE found[8];
  CK_ATTRIBUTE q[] = { { CKA_SEED, buf, sizeof(buf) } };
  CK_ULONG n = 0;
  CK_RV rv;
  memset(buf, 0, sizeof(buf));
  q[0].ulValueLen = sizeof(buf);
  rv = f->C_GetAttributeValue(s, priv, q, 1);
  CHECK(rv == CKR_OK && q[0].ulValueLen == seedLen &&
        memcmp(buf, seed, seedLen) == 0,
        "%s open seed reads back (%lu bytes, rv=0x%lx)", what,
        (unsigned long)q[0].ulValueLen, (unsigned long)rv);
  if (rv != CKR_OK || q[0].ulValueLen != seedLen) {
    return;
  }
  n = seed_find(s, seed, seedLen, found, what);
  CHECK(n == 1 && found[0] == priv, "%s find by true seed hits exactly it",
        what);
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE h = 0;
  CK_OBJECT_HANDLE mpub = 0, mpriv = 0;
  int i;
  /* Widths: ML-DSA-44 expanded 2560 / seed 32; ML-KEM-512 dk 1632 /
   * seed 64; SLH-DSA-SHA2-128S secret 64 / seed 16. */
  static CK_BYTE dsaVal[2560];
  static CK_BYTE dsaSeedS[32], dsaSeedU[32], dsaSeedL[32], dsaSeedO[32];
  static CK_BYTE kemVal[1632];
  static CK_BYTE kemSeedS[64], kemSeedU[64], kemSeedL[64], kemSeedO[64];
  static CK_BYTE slhVal[64];
  static CK_BYTE slhSeedS[16], slhSeedU[16], slhSeedL[16], slhSeedO[16];

  fill_pat(dsaVal, sizeof(dsaVal), 11);
  fill_pat(dsaSeedS, sizeof(dsaSeedS), 21);
  fill_pat(dsaSeedU, sizeof(dsaSeedU), 22);
  fill_pat(dsaSeedL, sizeof(dsaSeedL), 23);
  fill_pat(dsaSeedO, sizeof(dsaSeedO), 24);
  fill_pat(kemVal, sizeof(kemVal), 31);
  fill_pat(kemSeedS, sizeof(kemSeedS), 41);
  fill_pat(kemSeedU, sizeof(kemSeedU), 42);
  fill_pat(kemSeedL, sizeof(kemSeedL), 43);
  fill_pat(kemSeedO, sizeof(kemSeedO), 44);
  fill_pat(slhVal, sizeof(slhVal), 51);
  fill_pat(slhSeedS, sizeof(slhSeedS), 61);
  fill_pat(slhSeedU, sizeof(slhSeedU), 62);
  fill_pat(slhSeedL, sizeof(slhSeedL), 63);
  fill_pat(slhSeedO, sizeof(slhSeedO), 64);

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

  /* ML-DSA-44: sensitive, unextractable, legacy, open. */
  if (import_priv(sess, CKK_ML_DSA, CKP_ML_DSA_44, dsaVal, sizeof(dsaVal),
                  dsaSeedS, sizeof(dsaSeedS), 1, CK_TRUE, 1, CK_TRUE,
                  "ML-DSA sensitive", &h)) {
    check_sealed(sess, h, dsaSeedS, sizeof(dsaSeedS), "ML-DSA sensitive");
  }
  if (import_priv(sess, CKK_ML_DSA, CKP_ML_DSA_44, dsaVal, sizeof(dsaVal),
                  dsaSeedU, sizeof(dsaSeedU), 1, CK_FALSE, 1, CK_FALSE,
                  "ML-DSA unextractable", &h)) {
    check_sealed(sess, h, dsaSeedU, sizeof(dsaSeedU), "ML-DSA unextractable");
  }
  if (import_priv(sess, CKK_ML_DSA, CKP_ML_DSA_44, dsaVal, sizeof(dsaVal),
                  dsaSeedL, sizeof(dsaSeedL), 0, CK_FALSE, 0, CK_FALSE,
                  "ML-DSA legacy", &h)) {
    check_sealed(sess, h, dsaSeedL, sizeof(dsaSeedL), "ML-DSA legacy");
  }
  if (import_priv(sess, CKK_ML_DSA, CKP_ML_DSA_44, dsaVal, sizeof(dsaVal),
                  dsaSeedO, sizeof(dsaSeedO), 1, CK_FALSE, 1, CK_TRUE,
                  "ML-DSA open", &h)) {
    check_open(sess, h, dsaSeedO, sizeof(dsaSeedO), "ML-DSA open");
  }

  /* ML-KEM-512: sensitive, unextractable, legacy, open. */
  if (import_priv(sess, CKK_ML_KEM, CKP_ML_KEM_512, kemVal, sizeof(kemVal),
                  kemSeedS, sizeof(kemSeedS), 1, CK_TRUE, 1, CK_TRUE,
                  "ML-KEM sensitive", &h)) {
    check_sealed(sess, h, kemSeedS, sizeof(kemSeedS), "ML-KEM sensitive");
  }
  if (import_priv(sess, CKK_ML_KEM, CKP_ML_KEM_512, kemVal, sizeof(kemVal),
                  kemSeedU, sizeof(kemSeedU), 1, CK_FALSE, 1, CK_FALSE,
                  "ML-KEM unextractable", &h)) {
    check_sealed(sess, h, kemSeedU, sizeof(kemSeedU), "ML-KEM unextractable");
  }
  if (import_priv(sess, CKK_ML_KEM, CKP_ML_KEM_512, kemVal, sizeof(kemVal),
                  kemSeedL, sizeof(kemSeedL), 0, CK_FALSE, 0, CK_FALSE,
                  "ML-KEM legacy", &h)) {
    check_sealed(sess, h, kemSeedL, sizeof(kemSeedL), "ML-KEM legacy");
  }
  if (import_priv(sess, CKK_ML_KEM, CKP_ML_KEM_512, kemVal, sizeof(kemVal),
                  kemSeedO, sizeof(kemSeedO), 1, CK_FALSE, 1, CK_TRUE,
                  "ML-KEM open", &h)) {
    check_open(sess, h, kemSeedO, sizeof(kemSeedO), "ML-KEM open");
  }

  /* SLH-DSA-SHA2-128S: sensitive, unextractable, legacy, open. */
  if (import_priv(sess, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S, slhVal,
                  sizeof(slhVal), slhSeedS, sizeof(slhSeedS), 1, CK_TRUE, 1,
                  CK_TRUE, "SLH-DSA sensitive", &h)) {
    check_sealed(sess, h, slhSeedS, sizeof(slhSeedS), "SLH-DSA sensitive");
  }
  if (import_priv(sess, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S, slhVal,
                  sizeof(slhVal), slhSeedU, sizeof(slhSeedU), 1, CK_FALSE, 1,
                  CK_FALSE, "SLH-DSA unextractable", &h)) {
    check_sealed(sess, h, slhSeedU, sizeof(slhSeedU), "SLH-DSA unextractable");
  }
  if (import_priv(sess, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S, slhVal,
                  sizeof(slhVal), slhSeedL, sizeof(slhSeedL), 0, CK_FALSE, 0,
                  CK_FALSE, "SLH-DSA legacy", &h)) {
    check_sealed(sess, h, slhSeedL, sizeof(slhSeedL), "SLH-DSA legacy");
  }
  if (import_priv(sess, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S, slhVal,
                  sizeof(slhVal), slhSeedO, sizeof(slhSeedO), 1, CK_FALSE, 1,
                  CK_TRUE, "SLH-DSA open", &h)) {
    check_open(sess, h, slhSeedO, sizeof(slhSeedO), "SLH-DSA open");
  }

  /* A generated sealed ML-DSA pair stamps its own seed and seals it. */
  {
    CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE mkt = CKK_ML_DSA;
    CK_ULONG mset44 = CKP_ML_DSA_44;
    CK_MECHANISM mkgm;
    CK_ATTRIBUTE mpubT[5];
    CK_ATTRIBUTE mprivT[6];
    CK_BYTE buf[128];
    CK_ATTRIBUTE q[] = { { CKA_SEED, buf, sizeof(buf) } };
    mkgm.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;
    mkgm.pParameter = NULL_PTR;
    mkgm.ulParameterLen = 0;
    mpubT[0].type = CKA_CLASS;
    mpubT[0].pValue = &pcls;
    mpubT[0].ulValueLen = sizeof(pcls);
    mpubT[1].type = CKA_KEY_TYPE;
    mpubT[1].pValue = &mkt;
    mpubT[1].ulValueLen = sizeof(mkt);
    mpubT[2].type = CKA_PARAMETER_SET;
    mpubT[2].pValue = &mset44;
    mpubT[2].ulValueLen = sizeof(mset44);
    mpubT[3].type = CKA_TOKEN;
    mpubT[3].pValue = &bFalse;
    mpubT[3].ulValueLen = sizeof(bFalse);
    mpubT[4].type = CKA_VERIFY;
    mpubT[4].pValue = &bTrue;
    mpubT[4].ulValueLen = sizeof(bTrue);
    mprivT[0].type = CKA_CLASS;
    mprivT[0].pValue = &scls;
    mprivT[0].ulValueLen = sizeof(scls);
    mprivT[1].type = CKA_KEY_TYPE;
    mprivT[1].pValue = &mkt;
    mprivT[1].ulValueLen = sizeof(mkt);
    mprivT[2].type = CKA_TOKEN;
    mprivT[2].pValue = &bFalse;
    mprivT[2].ulValueLen = sizeof(bFalse);
    mprivT[3].type = CKA_SENSITIVE;
    mprivT[3].pValue = &bTrue;
    mprivT[3].ulValueLen = sizeof(bTrue);
    mprivT[4].type = CKA_EXTRACTABLE;
    mprivT[4].pValue = &bFalse;
    mprivT[4].ulValueLen = sizeof(bFalse);
    mprivT[5].type = CKA_SIGN;
    mprivT[5].pValue = &bTrue;
    mprivT[5].ulValueLen = sizeof(bTrue);
    rv = f->C_GenerateKeyPair(sess, &mkgm, mpubT, 5, mprivT, 6, &mpub,
                              &mpriv);
    CHECK(rv == CKR_OK && mpub != 0 && mpriv != 0,
          "sealed ML-DSA pair mints (rv=0x%lx)", (unsigned long)rv);
    if (rv == CKR_OK && mpub != 0 && mpriv != 0) {
      track(mpub);
      track(mpriv);
      memset(buf, 0xA5, sizeof(buf));
      q[0].ulValueLen = sizeof(buf);
      rv = f->C_GetAttributeValue(sess, mpriv, q, 1);
      CHECK(rv == CKR_ATTRIBUTE_SENSITIVE,
            "generated ML-DSA seed read refused (rv=0x%lx)",
            (unsigned long)rv);
      CHECK(q[0].ulValueLen == CK_UNAVAILABLE_INFORMATION,
            "generated ML-DSA seed length unavailable (len=0x%lx)",
            (unsigned long)q[0].ulValueLen);
      CHECK(filled_canary(buf, sizeof(buf)),
            "generated ML-DSA seed buffer untouched");
    }
  }

  for (i = 0; i < g_nall; i++) {
    rv = f->C_DestroyObject(sess, g_all[i]);
    CHECK(rv == CKR_OK, "object destroyed");
  }

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_seed_sealed (sealed PQC seeds withhold)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
