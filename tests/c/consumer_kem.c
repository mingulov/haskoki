/* tests/c/consumer_kem.c -- C_EncapsulateKey/C_DecapsulateKey live pins.
 *
 * Drives the routed 3.2 KEM entries through the built shared module:
 * ML-KEM keygen on all three sets, the query/short/sufficient
 * encapsulate legs, decapsulation agreement, implicit rejection of
 * tampered ciphertexts, and every typed refusal (params, mechanism,
 * key type, usage marks, template, ciphertext width, keygen set,
 * non-canonical import).
 *
 * Scenario (3.2 table; encapsulate exists only there):
 *   - keygen 512/768/1024 via CKA_PARAMETER_SET mints pairs
 *   - keygen with an unknown set is CKR_TEMPLATE_INCONSISTENT
 *   - NULL out-buffer queries the ct length (768/1088/1568), no key
 *   - short buffer is CKR_BUFFER_TOO_SMALL with the length, no key
 *   - sufficient buffer lands ct bytes plus one AES-256 secret
 *   - decaps recovers the same 32-byte secret (AES-256 object)
 *   - tampered ct decapsulates OK to a DIFFERENT secret (FIPS 203
 *     implicit rejection, never an error)
 *   - off-width ct is CKR_ARGUMENTS_BAD
 *   - non-empty mechanism params are CKR_MECHANISM_PARAM_INVALID
 *   - a non-KEM mechanism is CKR_MECHANISM_INVALID
 *   - a non-KEM key is CKR_KEY_TYPE_INCONSISTENT
 *   - a key without the usage mark is CKR_KEY_FUNCTION_NOT_PERMITTED
 *   - importing a non-canonical ek is CKR_ATTRIBUTE_VALUE_INVALID
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2
 * headers. Scenario lines carry "crypto:" (excluded from the proxy
 * parity diff; asserted strictly per mode). Proxy mode NULL-guards
 * the 3.x slots: a shim without C_EncapsulateKey skips via "invent:".
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_kem <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;
static int g_isProxy = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("FAIL [%s:%d]: ", __FILE__, __LINE__);                        \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("ok: ");                                                      \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

#define CHECKC(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("crypto: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("crypto: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

#define CHECKM(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("invent: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("invent: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

static char g_cfg_path[256];

static void write_config(void) {
  static const char body[] = "schema_version = 1\n"
                             "profile = \"real-crypto\"\n"
                             "[storage]\n"
                             "kind = \"memory\"\n"
                             "[engine]\n"
                             "kind = \"openssl\"\n"
                             "allow_synthetic_fallback = false\n"
                             "private_library_context = true\n"
                             "[trace]\n"
                             "enabled = false\n";
  char tmpl[] = "/tmp/haskoki-kem-XXXXXX";
  int fd = mkstemp(tmpl);
  size_t want;
  if (fd < 0) {
    perror("mkstemp");
    exit(2);
  }
  want = sizeof(body) - 1;
  if (write(fd, body, want) != (ssize_t)want) {
    perror("write");
    exit(2);
  }
  close(fd);
  snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", tmpl);
  if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

/* The KEM scenario over raw function pointers (3.2 table only:
 * encapsulate/decapsulate exist only there). */
typedef CK_RV (*fn_open_session)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR,
                                CK_NOTIFY, CK_SESSION_HANDLE_PTR);
typedef CK_RV (*fn_close_session)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_generate_keypair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                     CK_ATTRIBUTE_PTR, CK_ULONG,
                                     CK_ATTRIBUTE_PTR, CK_ULONG,
                                     CK_OBJECT_HANDLE_PTR,
                                     CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*fn_generate_key)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                 CK_ATTRIBUTE_PTR, CK_ULONG,
                                 CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*fn_create_object)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR,
                                  CK_ULONG, CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*fn_get_attr)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                             CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*fn_encapsulate)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR,
                                CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*fn_decapsulate)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*fn_get_slot_list)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);

static void run_kem_scenario(const char *tag, fn_open_session pOpen,
                             fn_close_session pClose,
                             fn_generate_keypair pGenPair,
                             fn_generate_key pGenKey,
                             fn_create_object pCreate, fn_get_attr pGetAttr,
                             fn_encapsulate pEncaps, fn_decapsulate pDecaps,
                             fn_get_slot_list pSlots) {
  static const CK_ULONG ctLens[3] = {768, 1088, 1568};
  static const CK_ULONG ckps[3] = {CKP_ML_KEM_512, CKP_ML_KEM_768,
                                   CKP_ML_KEM_1024};
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY,
                  ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE kkt = CKK_ML_KEM, akt = CKK_AES, gkt = CKK_GENERIC_SECRET;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_ULONG vlen32 = 32, vlen16 = 16;
  CK_MECHANISM kgm, kem, bad, aeskg;
  CK_ATTRIBUTE pubT[6], privT[6], secT[6], shortPubT[5];
  CK_OBJECT_HANDLE pubs[3] = {0, 0, 0}, privs[3] = {0, 0, 0};
  CK_OBJECT_HANDLE secret = 0, recovered = 0, aesKey = 0, tmp = 0;
  CK_BYTE ct[1600], ss1[32], ss2[32];
  CK_ULONG ctLen = 0;
  CK_BYTE badEk[1568];
  CK_ATTRIBUTE getT[1];
  CK_RV rv;
  int i;

  if (pEncaps == NULL || pDecaps == NULL) {
    CHECKM(g_isProxy, "%s: NULL KEM slots only behind the shim", tag);
    return;
  }
  CHECKC(pEncaps != NULL && pDecaps != NULL, "%s: KEM slots wired", tag);

  rv = pOpen(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
             &sess);
  if (rv == CKR_SLOT_ID_INVALID) {
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (pSlots(0, psl, &pn) == CKR_OK && pn >= 1) {
      rv = pOpen(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                 NULL_PTR, NULL_PTR, &sess);
    }
  }
  CHECKC(rv == CKR_OK, "%s: session opens", tag);
  if (rv != CKR_OK) {
    return;
  }

  kgm.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  kem.mechanism = CKM_ML_KEM;
  kem.pParameter = NULL_PTR;
  kem.ulParameterLen = 0;

  /* The shared-secret template (AES-256, extractable for readback). */
  secT[0].type = CKA_CLASS;
  secT[0].pValue = &ckcls;
  secT[0].ulValueLen = sizeof(ckcls);
  secT[1].type = CKA_KEY_TYPE;
  secT[1].pValue = &akt;
  secT[1].ulValueLen = sizeof(akt);
  secT[2].type = CKA_VALUE_LEN;
  secT[2].pValue = &vlen32;
  secT[2].ulValueLen = sizeof(vlen32);
  secT[3].type = CKA_TOKEN;
  secT[3].pValue = &bFalse;
  secT[3].ulValueLen = sizeof(bFalse);
  secT[4].type = CKA_EXTRACTABLE;
  secT[4].pValue = &bTrue;
  secT[4].ulValueLen = sizeof(bTrue);
  secT[5].type = CKA_SENSITIVE;
  secT[5].pValue = &bFalse;
  secT[5].ulValueLen = sizeof(bFalse);

  /* Keygen on all three sets via CKA_PARAMETER_SET. */
  for (i = 0; i < 3; i++) {
    pubT[0].type = CKA_CLASS;
    pubT[0].pValue = &pcls;
    pubT[0].ulValueLen = sizeof(pcls);
    pubT[1].type = CKA_KEY_TYPE;
    pubT[1].pValue = &kkt;
    pubT[1].ulValueLen = sizeof(kkt);
    pubT[2].type = CKA_PARAMETER_SET;
    pubT[2].pValue = (CK_VOID_PTR)&ckps[i];
    pubT[2].ulValueLen = sizeof(ckps[i]);
    pubT[3].type = CKA_TOKEN;
    pubT[3].pValue = &bFalse;
    pubT[3].ulValueLen = sizeof(bFalse);
    pubT[4].type = CKA_ENCAPSULATE;
    pubT[4].pValue = &bTrue;
    pubT[4].ulValueLen = sizeof(bTrue);
    pubT[5].type = CKA_EXTRACTABLE;
    pubT[5].pValue = &bTrue;
    pubT[5].ulValueLen = sizeof(bTrue);
    privT[0].type = CKA_CLASS;
    privT[0].pValue = &scls;
    privT[0].ulValueLen = sizeof(scls);
    privT[1].type = CKA_KEY_TYPE;
    privT[1].pValue = &kkt;
    privT[1].ulValueLen = sizeof(kkt);
    privT[2].type = CKA_TOKEN;
    privT[2].pValue = &bFalse;
    privT[2].ulValueLen = sizeof(bFalse);
    privT[3].type = CKA_DECAPSULATE;
    privT[3].pValue = &bTrue;
    privT[3].ulValueLen = sizeof(bTrue);
    privT[4].type = CKA_EXTRACTABLE;
    privT[4].pValue = &bTrue;
    privT[4].ulValueLen = sizeof(bTrue);
    privT[5].type = CKA_SENSITIVE;
    privT[5].pValue = &bFalse;
    privT[5].ulValueLen = sizeof(bFalse);
    rv = pGenPair(sess, &kgm, pubT, 6, privT, 6, &pubs[i], &privs[i]);
    CHECKC(rv == CKR_OK && pubs[i] != 0 && privs[i] != 0,
           "%s: ML-KEM set %d pair mints", tag, i);
  }

  /* Unknown keygen set refuses. */
  {
    CK_ULONG badSet = 7;
    CK_ATTRIBUTE badT[3];
    badT[0].type = CKA_CLASS;
    badT[0].pValue = &pcls;
    badT[0].ulValueLen = sizeof(pcls);
    badT[1].type = CKA_KEY_TYPE;
    badT[1].pValue = &kkt;
    badT[1].ulValueLen = sizeof(kkt);
    badT[2].type = CKA_PARAMETER_SET;
    badT[2].pValue = &badSet;
    badT[2].ulValueLen = sizeof(badSet);
    rv = pGenPair(sess, &kgm, badT, 3, privT, 6, &tmp, &tmp);
    CHECKC(rv == CKR_TEMPLATE_INCONSISTENT,
           "%s: unknown keygen set is INCONSISTENT", tag);
  }

  /* Query/short/sufficient per set (768 exercised fully below). */
  for (i = 0; i < 3; i++) {
    ctLen = 0;
    secret = 0;
    rv = pEncaps(sess, &kem, pubs[i], secT, 6, NULL_PTR, &ctLen, &secret);
    CHECKC(rv == CKR_OK && ctLen == ctLens[i] && secret == 0,
           "%s: set %d queries %lu bytes, no key", tag, i,
           (unsigned long)ctLens[i]);
    ctLen = 100;
    secret = 0;
    rv = pEncaps(sess, &kem, pubs[i], secT, 6, ct, &ctLen, &secret);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && ctLen == ctLens[i] && secret == 0,
           "%s: set %d short reports %lu bytes, no key", tag, i,
           (unsigned long)ctLens[i]);
  }

  /* Full 768 round-trip: encapsulate, read the secret, decapsulate,
   * read it back, compare. */
  ctLen = sizeof(ct);
  secret = 0;
  rv = pEncaps(sess, &kem, pubs[1], secT, 6, ct, &ctLen, &secret);
  CHECKC(rv == CKR_OK && ctLen == 1088 && secret != 0,
         "%s: 768 encapsulates 1088 bytes plus a secret", tag);
  getT[0].type = CKA_VALUE;
  getT[0].pValue = ss1;
  getT[0].ulValueLen = sizeof(ss1);
  rv = pGetAttr(sess, secret, getT, 1);
  CHECKC(rv == CKR_OK && getT[0].ulValueLen == 32,
         "%s: encaps secret reads 32 bytes", tag);
  recovered = 0;
  rv = pDecaps(sess, &kem, privs[1], secT, 6, ct, ctLen, &recovered);
  CHECKC(rv == CKR_OK && recovered != 0, "%s: 768 decapsulates", tag);
  getT[0].type = CKA_VALUE;
  getT[0].pValue = ss2;
  getT[0].ulValueLen = sizeof(ss2);
  rv = pGetAttr(sess, recovered, getT, 1);
  CHECKC(rv == CKR_OK && getT[0].ulValueLen == 32 &&
             memcmp(ss1, ss2, 32) == 0,
         "%s: decaps recovers the same secret", tag);

  /* Generic-secret output shape serves too. */
  secT[1].pValue = &gkt;
  recovered = 0;
  rv = pDecaps(sess, &kem, privs[1], secT, 6, ct, ctLen, &recovered);
  CHECKC(rv == CKR_OK && recovered != 0,
         "%s: generic-secret decaps serves", tag);
  secT[1].pValue = &akt;

  /* Tampered ciphertext: implicit rejection (OK, different secret). */
  ct[0] ^= 0xFF;
  recovered = 0;
  rv = pDecaps(sess, &kem, privs[1], secT, 6, ct, ctLen, &recovered);
  CHECKC(rv == CKR_OK && recovered != 0,
         "%s: tampered ct decapsulates (implicit rejection)", tag);
  getT[0].type = CKA_VALUE;
  getT[0].pValue = ss2;
  getT[0].ulValueLen = sizeof(ss2);
  rv = pGetAttr(sess, recovered, getT, 1);
  CHECKC(rv == CKR_OK && memcmp(ss1, ss2, 32) != 0,
         "%s: tampered secret differs", tag);
  ct[0] ^= 0xFF;

  /* Off-width ciphertext refuses. */
  rv = pDecaps(sess, &kem, privs[1], secT, 6, ct, 100, &recovered);
  CHECKC(rv == CKR_ENCRYPTED_DATA_LEN_RANGE, "%s: short ct is LEN_RANGE", tag);

  /* Non-empty mechanism params refuse on both entries. */
  {
    CK_BYTE junk[4] = {1, 2, 3, 4};
    CK_MECHANISM pm = kem;
    pm.pParameter = junk;
    pm.ulParameterLen = sizeof(junk);
    ctLen = sizeof(ct);
    rv = pEncaps(sess, &pm, pubs[1], secT, 6, ct, &ctLen, &tmp);
    CHECKC(rv == CKR_MECHANISM_PARAM_INVALID,
           "%s: encaps params refused", tag);
    rv = pDecaps(sess, &pm, privs[1], secT, 6, ct, 1088, &tmp);
    CHECKC(rv == CKR_MECHANISM_PARAM_INVALID,
           "%s: decaps params refused", tag);
  }

  /* A non-KEM mechanism refuses on both entries. */
  bad.mechanism = CKM_SHA256;
  bad.pParameter = NULL_PTR;
  bad.ulParameterLen = 0;
  ctLen = sizeof(ct);
  rv = pEncaps(sess, &bad, pubs[1], secT, 6, ct, &ctLen, &tmp);
  CHECKC(rv == CKR_MECHANISM_INVALID, "%s: encaps mech refused", tag);
  rv = pDecaps(sess, &bad, privs[1], secT, 6, ct, 1088, &tmp);
  CHECKC(rv == CKR_MECHANISM_INVALID, "%s: decaps mech refused", tag);

  /* A non-KEM key refuses with the type code. */
  {
    CK_ATTRIBUTE aesT[4];
    aeskg.mechanism = CKM_AES_KEY_GEN;
    aeskg.pParameter = NULL_PTR;
    aeskg.ulParameterLen = 0;
    aesT[0].type = CKA_CLASS;
    aesT[0].pValue = &ckcls;
    aesT[0].ulValueLen = sizeof(ckcls);
    aesT[1].type = CKA_KEY_TYPE;
    aesT[1].pValue = &akt;
    aesT[1].ulValueLen = sizeof(akt);
    aesT[2].type = CKA_VALUE_LEN;
    aesT[2].pValue = &vlen16;
    aesT[2].ulValueLen = sizeof(vlen16);
    aesT[3].type = CKA_TOKEN;
    aesT[3].pValue = &bFalse;
    aesT[3].ulValueLen = sizeof(bFalse);
    /* No usage mark: the type check precedes the usage check. */
    rv = pGenKey(sess, &aeskg, aesT, 4, &aesKey);
    CHECKC(rv == CKR_OK && aesKey != 0, "%s: AES key mints", tag);
    ctLen = sizeof(ct);
    rv = pEncaps(sess, &kem, aesKey, secT, 6, ct, &ctLen, &tmp);
    CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
           "%s: AES key encaps is TYPE_INCONSISTENT", tag);
    rv = pDecaps(sess, &kem, aesKey, secT, 6, ct, 1088, &tmp);
    CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
           "%s: AES key decaps is TYPE_INCONSISTENT", tag);
  }

  /* A key without the usage mark refuses with the usage code. */
  {
    CK_ATTRIBUTE noT[6];
    CK_OBJECT_HANDLE nopub = 0, nopriv = 0;
    memcpy(noT, pubT, sizeof(pubT));
    noT[4].pValue = &bFalse;
    rv = pGenPair(sess, &kgm, noT, 6, privT, 6, &nopub, &nopriv);
    CHECKC(rv == CKR_OK && nopub != 0, "%s: unmarked pair mints", tag);
    ctLen = sizeof(ct);
    rv = pEncaps(sess, &kem, nopub, secT, 6, ct, &ctLen, &tmp);
    CHECKC(rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "%s: unmarked encaps is NOT_PERMITTED", tag);
  }

  /* A non-canonical ek (every coefficient 0xFFF) refuses at import
   * with the spec-correct code. */
  {
    CK_OBJECT_HANDLE badPub = 0;
    CK_ATTRIBUTE impT[5];
    CK_ULONG set768 = CKP_ML_KEM_768;
    CK_ULONG ekLen = 1184;
    (void)ekLen;
    memset(badEk, 0xFF, 1184);
    impT[0].type = CKA_CLASS;
    impT[0].pValue = &pcls;
    impT[0].ulValueLen = sizeof(pcls);
    impT[1].type = CKA_KEY_TYPE;
    impT[1].pValue = &kkt;
    impT[1].ulValueLen = sizeof(kkt);
    impT[2].type = CKA_PARAMETER_SET;
    impT[2].pValue = &set768;
    impT[2].ulValueLen = sizeof(set768);
    impT[3].type = CKA_VALUE;
    impT[3].pValue = badEk;
    impT[3].ulValueLen = 1184;
    impT[4].type = CKA_TOKEN;
    impT[4].pValue = &bFalse;
    impT[4].ulValueLen = sizeof(bFalse);
    rv = pCreate(sess, impT, 5, &badPub);
    CHECKC(rv == CKR_ATTRIBUTE_VALUE_INVALID,
           "%s: non-canonical ek import is VALUE_INVALID", tag);
  }

  /* A short public template (no set) still mints (default 768). */
  {
    CK_OBJECT_HANDLE dpub = 0, dpriv = 0;
    shortPubT[0].type = CKA_CLASS;
    shortPubT[0].pValue = &pcls;
    shortPubT[0].ulValueLen = sizeof(pcls);
    shortPubT[1].type = CKA_KEY_TYPE;
    shortPubT[1].pValue = &kkt;
    shortPubT[1].ulValueLen = sizeof(kkt);
    shortPubT[2].type = CKA_TOKEN;
    shortPubT[2].pValue = &bFalse;
    shortPubT[2].ulValueLen = sizeof(bFalse);
    shortPubT[3].type = CKA_ENCAPSULATE;
    shortPubT[3].pValue = &bTrue;
    shortPubT[3].ulValueLen = sizeof(bTrue);
    shortPubT[4].type = CKA_EXTRACTABLE;
    shortPubT[4].pValue = &bTrue;
    shortPubT[4].ulValueLen = sizeof(bTrue);
    rv = pGenPair(sess, &kgm, shortPubT, 5, privT, 6, &dpub, &dpriv);
    CHECKC(rv == CKR_OK && dpub != 0 && dpriv != 0,
           "%s: pair mints without a set (default 768)", tag);
    ctLen = 0;
    rv = pEncaps(sess, &kem, dpub, secT, 6, NULL_PTR, &ctLen, &tmp);
    CHECKC(rv == CKR_OK && ctLen == 1088,
           "%s: default pair queries 1088 bytes", tag);
  }

  rv = pClose(sess);
  CHECKC(rv == CKR_OK, "%s: session closes", tag);
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_C_GetInterface pGetInterface;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_FUNCTION_LIST_3_2_PTR tab32 = NULL_PTR;
  CK_INTERFACE_PTR pIf = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  const char *topo;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  g_isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", g_isProxy ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  pGetInterface = (CK_C_GetInterface)dlsym(handle, "C_GetInterface");
  CHECK(pGetList && pGetInterface, "discovery symbols resolve");
  if (!pGetList || !pGetInterface) {
    return 2;
  }
  rv = pGetList(&legacy);
  CHECK(rv == CKR_OK && legacy != NULL_PTR, "legacy table fetched");
  if (!legacy) {
    return 2;
  }

  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &pIf, 0);
  CHECK(rv == CKR_OK && pIf != NULL_PTR, "GetInterface selects 3.2");
  if (pIf != NULL_PTR) {
    tab32 = (CK_FUNCTION_LIST_3_2_PTR)pIf->pFunctionList;
  }
  if (!tab32) {
    return 2;
  }

  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok (rv=%lu)",
        (unsigned long)rv);
  if (rv != CKR_OK) {
    return 2;
  }

  run_kem_scenario("3.2", tab32->C_OpenSession, tab32->C_CloseSession,
                   tab32->C_GenerateKeyPair, tab32->C_GenerateKey,
                   tab32->C_CreateObject, tab32->C_GetAttributeValue,
                   tab32->C_EncapsulateKey, tab32->C_DecapsulateKey,
                   tab32->C_GetSlotList);

  rv = tab32->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");

  unlink(g_cfg_path);
  if (g_failures) {
    printf("FAIL: %d check(s) failed\n", g_failures);
    return 1;
  }
  printf("PASS: kem consumer\n");
  return 0;
}
