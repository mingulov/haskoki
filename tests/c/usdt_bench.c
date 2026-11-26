/* USDT dormant-probe bench workload (single capability).
 *
 * Usage: usdt_bench <libhaskoki.so> [iterations]
 * Warms up, then runs N AES-256-CBC-PAD one-shot encrypt+decrypt
 * round-trips (decrypt verified by memcmp every iteration) and
 * prints BENCH-NS:<nanoseconds> ITERS:<n> on stdout. Any PKCS#11
 * failure or mismatch exits nonzero: the timing is only valid
 * when every measured op was real. Driven by
 * scripts/test-usdt-bench.sh, which compares the off vs unattached
 * builds through this same binary.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>

#include "pkcs11.h"

#define FAIL(msg) do { \
    fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
    return 1; \
  } while (0)
#define CHECKRV(rv, msg) do { \
    if ((rv) != CKR_OK) { \
      fprintf(stderr, "FAIL: %s: rv=0x%lx (line %d)\n", msg, \
              (unsigned long)(rv), __LINE__); \
      return 1; \
    } \
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
  char tmpl[] = "/tmp/haskoki-usdt-bench-XXXXXX";
  int fd = mkstemp(tmpl);
  size_t want = sizeof(body) - 1;
  if (fd < 0) { perror("mkstemp"); exit(2); }
  if (write(fd, body, want) != (ssize_t)want) { perror("write"); exit(2); }
  close(fd);
  snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", tmpl);
  if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) { perror("setenv"); exit(2); }
}

static unsigned long long now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (unsigned long long)ts.tv_sec * 1000000000ull
    + (unsigned long long)ts.tv_nsec;
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f;
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE key = 0;
  CK_MECHANISM kgm, em, dm;
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE kt = CKK_AES;
  CK_ULONG klen = 32;
  CK_BBOOL bFalse = CK_FALSE;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_VALUE_LEN, &klen, sizeof(klen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) }
  };
  static CK_BYTE iv[16] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
  };
  static CK_BYTE pt[64];
  CK_BYTE ct[96], back[96];
  CK_ULONG ctLen, backLen;
  long iters = 300, warmup = 50, i;
  unsigned long long t0 = 0, t1 = 0;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s <libhaskoki.so> [iterations]\n", argv[0]);
    return 2;
  }
  if (argc == 3) {
    iters = atol(argv[2]);
    if (iters < 1 || iters > 1000000) {
      fprintf(stderr, "iterations out of range: %s\n", argv[2]);
      return 2;
    }
  }
  for (i = 0; i < 64; i++) pt[i] = (CK_BYTE)(0xA0 + i);

  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (!pGetList) FAIL("C_GetFunctionList resolves");
  rv = pGetList(&f);
  if (rv != CKR_OK || !f) FAIL("function list fetches");
  rv = f->C_Initialize(NULL_PTR);
  CHECKRV(rv, "C_Initialize");

  rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                        NULL_PTR, &sess);
  if (rv == CKR_SLOT_ID_INVALID) {
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
      rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
    }
  }
  if (rv != CKR_OK || sess == 0) FAIL("session opens");

  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = f->C_GenerateKey(sess, &kgm, tmpl, 4, &key);
  if (rv != CKR_OK || key == 0) FAIL("AES-256 keygen");

  em.mechanism = CKM_AES_CBC_PAD;
  em.pParameter = iv;
  em.ulParameterLen = sizeof(iv);
  dm.mechanism = CKM_AES_CBC_PAD;
  dm.pParameter = iv;
  dm.ulParameterLen = sizeof(iv);

  for (i = 0; i < warmup + iters; i++) {
    if (i == warmup) t0 = now_ns();
    rv = f->C_EncryptInit(sess, &em, key);
    if (rv != CKR_OK) FAIL("EncryptInit");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, pt, sizeof(pt), ct, &ctLen);
    if (rv != CKR_OK) FAIL("Encrypt");
    rv = f->C_DecryptInit(sess, &dm, key);
    if (rv != CKR_OK) FAIL("DecryptInit");
    backLen = sizeof(back);
    rv = f->C_Decrypt(sess, ct, ctLen, back, &backLen);
    if (rv != CKR_OK) FAIL("Decrypt");
    if (backLen != sizeof(pt) || memcmp(back, pt, sizeof(pt)) != 0)
      FAIL("round-trip mismatch");
  }
  t1 = now_ns();

  printf("BENCH-NS:%llu ITERS:%ld\n", t1 - t0, iters);
  rv = f->C_CloseSession(sess);
  CHECKRV(rv, "CloseSession");
  rv = f->C_Finalize(NULL_PTR);
  CHECKRV(rv, "Finalize");
  return 0;
}
