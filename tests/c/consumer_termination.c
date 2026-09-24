/* tests/c/consumer_termination.c — direct-load consumer: op termination.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and pins the spec termination rule — every
 * error other than CKR_BUFFER_TOO_SMALL terminates the active
 * operation; only the successful length query keeps the slot:
 *   - NULL data/length pointers on one-shot/update/final refuse
 *     ARGUMENTS_BAD and terminate (a re-init succeeds, it is not
 *     OPERATION_ACTIVE), for digest/sign/verify/encrypt/decrypt
 *   - one-shot over buffered multipart input denies OPERATION_ACTIVE
 *     and terminates (a final finds NOT_INITIALIZED, a re-init works)
 *   - an empty-output size query reports length 0 and keeps the slot
 *     for the recall (AES-ECB decrypt of empty input)
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_termination <path-to-libhaskoki.so>
 *
 * NULL-pointer legs are direct-only (isProxy-gated): the proxy shim
 * interposes its own NULL handling, so those pins assert our
 * module's contract, not the shim's. All other legs run in both
 * topologies under scripts/test-proxy-parity.sh.
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
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
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

/* Hermetic config: real-crypto engine, trace off (no stray files),
 * memory storage. */
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
  char tmpl[] = "/tmp/haskoki-consumer-XXXXXX";
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

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f = NULL_PTR;
  CK_RV rv;
  CK_SLOT_ID slots[16];
  CK_ULONG nslots = 16;
  CK_SESSION_HANDLE sess = 0;
  CK_MECHANISM mech, kgm, em;
  CK_OBJECT_HANDLE aesKey = 0, hmacKey = 0;
  CK_OBJECT_CLASS cls;
  CK_KEY_TYPE kt;
  CK_ULONG vlen;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_BYTE buf[64];
  CK_ULONG len;
  const char *topo;
  int isProxy;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (pGetList == NULL) {
    fprintf(stderr, "dlsym C_GetFunctionList failed: %s\n", dlerror());
    return 2;
  }
  rv = pGetList(&f);
  if (rv != CKR_OK || f == NULL_PTR) {
    fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "initialize ok");
  rv = f->C_GetSlotList(0, slots, &nslots);
  CHECK(rv == CKR_OK && nslots >= 1, "slot list ok");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK && sess != 0, "session opens");

  /* Keys: AES-128 for cipher, generic secret for HMAC sign/verify. */
  cls = CKO_SECRET_KEY;
  kt = CKK_AES;
  vlen = 16;
  {
    CK_ATTRIBUTE tmpl[] = {
      { CKA_CLASS, &cls, sizeof(cls) },
      { CKA_KEY_TYPE, &kt, sizeof(kt) },
      { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };
    kgm.mechanism = CKM_AES_KEY_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    rv = f->C_GenerateKey(sess, &kgm, tmpl, 6, &aesKey);
    CHECK(rv == CKR_OK && aesKey != 0, "AES keygen ok");
  }
  kt = CKK_GENERIC_SECRET;
  vlen = 32;
  {
    CK_ATTRIBUTE tmpl[] = {
      { CKA_CLASS, &cls, sizeof(cls) },
      { CKA_KEY_TYPE, &kt, sizeof(kt) },
      { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    kgm.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    rv = f->C_GenerateKey(sess, &kgm, tmpl, 6, &hmacKey);
    CHECK(rv == CKR_OK && hmacKey != 0, "generic-secret keygen ok");
  }

  /* ---- digest: NULL args terminate ---- */
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = f->C_DigestInit(sess, &mech);
  CHECK(rv == CKR_OK, "digest init ok");
  len = sizeof(buf);
  if (!isProxy) {
  rv = f->C_Digest(sess, NULL_PTR, 3, buf, &len);
  CHECK(rv == CKR_ARGUMENTS_BAD, "digest NULL data refused");
  rv = f->C_DigestInit(sess, &mech);
  CHECK(rv == CKR_OK, "re-init after NULL data ok (terminated)");
  }
  len = sizeof(buf);
  if (!isProxy) {
  rv = f->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, NULL_PTR);
  CHECK(rv == CKR_ARGUMENTS_BAD, "digest NULL length refused");
  rv = f->C_DigestInit(sess, &mech);
  CHECK(rv == CKR_OK, "re-init after NULL length ok (terminated)");
  }
  if (!isProxy) {
  rv = f->C_DigestUpdate(sess, NULL_PTR, 3);
  CHECK(rv == CKR_ARGUMENTS_BAD, "digest update NULL data refused");
  rv = f->C_DigestInit(sess, &mech);
  CHECK(rv == CKR_OK, "re-init after NULL update ok (terminated)");
  }
  if (!isProxy) {
  rv = f->C_DigestFinal(sess, buf, NULL_PTR);
  CHECK(rv == CKR_ARGUMENTS_BAD, "digest final NULL length refused");
  rv = f->C_DigestInit(sess, &mech);
  CHECK(rv == CKR_OK, "re-init after NULL final ok (terminated)");
  }
  rv = f->C_DigestUpdate(sess, (CK_BYTE_PTR) "a", 1);
  CHECK(rv == CKR_OK, "digest update buffers");
  len = sizeof(buf);
  rv = f->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
  CHECK(rv == CKR_OPERATION_ACTIVE, "digest one-shot over buffered is ACTIVE");
  len = sizeof(buf);
  rv = f->C_DigestFinal(sess, buf, &len);
  CHECK(rv == CKR_OPERATION_NOT_INITIALIZED,
        "digest final after refused one-shot is NOT_INITIALIZED");

  /* ---- sign (HMAC): NULL args terminate ---- */
  mech.mechanism = CKM_SHA256_HMAC;
  rv = f->C_SignInit(sess, &mech, hmacKey);
  CHECK(rv == CKR_OK, "sign init ok");
  len = sizeof(buf);
  if (!isProxy) {
  rv = f->C_Sign(sess, NULL_PTR, 3, buf, &len);
  CHECK(rv == CKR_ARGUMENTS_BAD, "sign NULL data refused");
  rv = f->C_SignInit(sess, &mech, hmacKey);
  CHECK(rv == CKR_OK, "re-init after NULL data ok (terminated)");
  }
  if (!isProxy) {
  rv = f->C_SignUpdate(sess, NULL_PTR, 3);
  CHECK(rv == CKR_ARGUMENTS_BAD, "sign update NULL data refused");
  rv = f->C_SignInit(sess, &mech, hmacKey);
  CHECK(rv == CKR_OK, "re-init after NULL update ok (terminated)");
  }
  len = sizeof(buf);
  if (!isProxy) {
  rv = f->C_Sign(sess, (CK_BYTE_PTR) "abc", 3, buf, NULL_PTR);
  CHECK(rv == CKR_ARGUMENTS_BAD, "sign NULL length refused");
  rv = f->C_SignInit(sess, &mech, hmacKey);
  CHECK(rv == CKR_OK, "re-init after NULL length ok (terminated)");
  }
  if (!isProxy) {
  rv = f->C_SignFinal(sess, buf, NULL_PTR);
  CHECK(rv == CKR_ARGUMENTS_BAD, "sign final NULL length refused");
  rv = f->C_SignInit(sess, &mech, hmacKey);
  CHECK(rv == CKR_OK, "re-init after NULL final ok (terminated)");
  }
  rv = f->C_SignUpdate(sess, (CK_BYTE_PTR) "a", 1);
  CHECK(rv == CKR_OK, "sign update buffers");
  len = sizeof(buf);
  rv = f->C_Sign(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
  CHECK(rv == CKR_OPERATION_ACTIVE, "sign one-shot over buffered is ACTIVE");
  len = sizeof(buf);
  rv = f->C_SignFinal(sess, buf, &len);
  CHECK(rv == CKR_OPERATION_NOT_INITIALIZED,
        "sign final after refused one-shot is NOT_INITIALIZED");

  /* ---- verify (HMAC): NULL args terminate ---- */
  {
    CK_BYTE sig[32];
    CK_ULONG sigLen = sizeof(sig);
    rv = f->C_SignInit(sess, &mech, hmacKey);
    CHECK(rv == CKR_OK, "sign init for witness ok");
    rv = f->C_Sign(sess, (CK_BYTE_PTR) "abc", 3, sig, &sigLen);
    CHECK(rv == CKR_OK && sigLen == 32, "witness signs");
    rv = f->C_VerifyInit(sess, &mech, hmacKey);
    CHECK(rv == CKR_OK, "verify init ok");
  if (!isProxy) {
    rv = f->C_Verify(sess, NULL_PTR, 3, sig, sigLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "verify NULL data refused");
    rv = f->C_VerifyInit(sess, &mech, hmacKey);
    CHECK(rv == CKR_OK, "re-init after NULL data ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_Verify(sess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, sigLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "verify NULL signature refused");
    rv = f->C_VerifyInit(sess, &mech, hmacKey);
    CHECK(rv == CKR_OK, "re-init after NULL signature ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_VerifyUpdate(sess, NULL_PTR, 3);
    CHECK(rv == CKR_ARGUMENTS_BAD, "verify update NULL data refused");
    rv = f->C_VerifyInit(sess, &mech, hmacKey);
    CHECK(rv == CKR_OK, "re-init after NULL update ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_VerifyFinal(sess, NULL_PTR, sigLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "verify final NULL signature refused");
    rv = f->C_VerifyInit(sess, &mech, hmacKey);
    CHECK(rv == CKR_OK, "re-init after NULL final ok (terminated)");
  }
    rv = f->C_VerifyUpdate(sess, (CK_BYTE_PTR) "a", 1);
    CHECK(rv == CKR_OK, "verify update buffers");
    rv = f->C_Verify(sess, (CK_BYTE_PTR) "abc", 3, sig, sigLen);
    CHECK(rv == CKR_OPERATION_ACTIVE, "verify one-shot over buffered is ACTIVE");
    rv = f->C_VerifyFinal(sess, sig, sigLen);
    CHECK(rv == CKR_OPERATION_NOT_INITIALIZED,
          "verify final after refused one-shot is NOT_INITIALIZED");
  }

  /* ---- encrypt/decrypt (AES-CBC-PAD): NULL args terminate ---- */
  {
    CK_BYTE iv[16] = { 0 };
    CK_BYTE ct[64], pt[64];
    CK_ULONG ctLen, ptLen, partLen;
    em.mechanism = CKM_AES_CBC_PAD;
    em.pParameter = iv;
    em.ulParameterLen = sizeof(iv);
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "encrypt init ok");
    ctLen = sizeof(ct);
  if (!isProxy) {
    rv = f->C_Encrypt(sess, NULL_PTR, 3, ct, &ctLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "encrypt NULL data refused");
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL data ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_Encrypt(sess, (CK_BYTE_PTR) "abc", 3, ct, NULL_PTR);
    CHECK(rv == CKR_ARGUMENTS_BAD, "encrypt NULL length refused");
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL length ok (terminated)");
  }
    partLen = sizeof(ct);
  if (!isProxy) {
    rv = f->C_EncryptUpdate(sess, NULL_PTR, 3, ct, &partLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "encrypt update NULL data refused");
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL update ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_EncryptUpdate(sess, (CK_BYTE_PTR) "abc", 3, ct, NULL_PTR);
    CHECK(rv == CKR_ARGUMENTS_BAD, "encrypt update NULL length refused");
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL update length ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_EncryptFinal(sess, ct, NULL_PTR);
    CHECK(rv == CKR_ARGUMENTS_BAD, "encrypt final NULL length refused");
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL final ok (terminated)");
  }
    partLen = sizeof(ct);
    rv = f->C_EncryptUpdate(sess, (CK_BYTE_PTR) "a", 1, ct, &partLen);
    CHECK(rv == CKR_OK && partLen == 0, "encrypt update buffers");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, (CK_BYTE_PTR) "d", 1, ct, &ctLen);
    CHECK(rv == CKR_OPERATION_ACTIVE, "encrypt one-shot over buffered is ACTIVE");
    ctLen = sizeof(ct);
    rv = f->C_EncryptFinal(sess, ct, &ctLen);
    CHECK(rv == CKR_OPERATION_NOT_INITIALIZED,
          "encrypt final after refused one-shot is NOT_INITIALIZED");
    /* One full encrypt for the decrypt legs below. */
    rv = f->C_EncryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "encrypt init for decrypt legs ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, (CK_BYTE_PTR) "abc", 3, ct, &ctLen);
    CHECK(rv == CKR_OK && ctLen == 16, "encrypt yields one block");

    rv = f->C_DecryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "decrypt init ok");
    ptLen = sizeof(pt);
  if (!isProxy) {
    rv = f->C_Decrypt(sess, NULL_PTR, ctLen, pt, &ptLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "decrypt NULL data refused");
    rv = f->C_DecryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL data ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_Decrypt(sess, ct, ctLen, pt, NULL_PTR);
    CHECK(rv == CKR_ARGUMENTS_BAD, "decrypt NULL length refused");
    rv = f->C_DecryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL length ok (terminated)");
  }
    partLen = sizeof(pt);
  if (!isProxy) {
    rv = f->C_DecryptUpdate(sess, NULL_PTR, ctLen, pt, &partLen);
    CHECK(rv == CKR_ARGUMENTS_BAD, "decrypt update NULL data refused");
    rv = f->C_DecryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL update ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_DecryptUpdate(sess, ct, ctLen, pt, NULL_PTR);
    CHECK(rv == CKR_ARGUMENTS_BAD, "decrypt update NULL length refused");
    rv = f->C_DecryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL update length ok (terminated)");
  }
  if (!isProxy) {
    rv = f->C_DecryptFinal(sess, pt, NULL_PTR);
    CHECK(rv == CKR_ARGUMENTS_BAD, "decrypt final NULL length refused");
    rv = f->C_DecryptInit(sess, &em, aesKey);
    CHECK(rv == CKR_OK, "re-init after NULL final ok (terminated)");
  }
  }

  /* ---- empty-output query keeps the slot for the recall ---- */
  {
    CK_BYTE out[64];
    CK_ULONG outLen;
    CK_SESSION_HANDLE esess = 0;
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &esess);
    CHECK(rv == CKR_OK && esess != 0, "empty-query session opens");
    em.mechanism = CKM_AES_ECB;
    em.pParameter = NULL_PTR;
    em.ulParameterLen = 0;
    rv = f->C_DecryptInit(esess, &em, aesKey);
    CHECK(rv == CKR_OK, "ECB decrypt init ok");
    outLen = 0;
    rv = f->C_Decrypt(esess, (CK_BYTE_PTR) "", 0, NULL_PTR, &outLen);
    CHECK(rv == CKR_OK && outLen == 0, "empty query reports 0");
    outLen = 0;
    rv = f->C_Decrypt(esess, (CK_BYTE_PTR) "", 0, out, &outLen);
    CHECK(rv == CKR_OK && outLen == 0, "empty recall completes");
    rv = f->C_CloseSession(esess);
    CHECK(rv == CKR_OK, "empty-query session closes");
  }

  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "session closes");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "finalize ok");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("PASS: consumer_termination (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
