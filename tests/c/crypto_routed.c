/* tests/c/crypto_routed.c — A1 routed-crypto C proof.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module, resolves the A1 trampolines
 * (haskoki_crypto_* in cbits/exports.c), and runs the digest
 * one-shot across the real export boundary, comparing against the
 * FIPS 180-4 SHA-256("abc") vector.
 *
 * Usage: crypto_routed <path-to-libhaskoki.so>
 * Exit status: 0 iff every check passes.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef void *CK_VOID_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_BYTE *CK_BYTE_PTR;

#define CKR_OK 0x00000000UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL

#define CKM_SHA256 0x00000250UL

typedef void *haskoki_crypto_ctx_t;
typedef haskoki_crypto_ctx_t (*fn_open)(void);
typedef void (*fn_close)(haskoki_crypto_ctx_t ctx);
typedef CK_RV (*fn_init)(haskoki_crypto_ctx_t ctx, CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_TYPE mech, CK_BYTE_PTR pParams,
                         CK_ULONG ulParamsLen);
typedef CK_RV (*fn_digest)(haskoki_crypto_ctx_t ctx, CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                           CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

/* FIPS 180-4: SHA-256("abc"). */
static const uint8_t kWant[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static int gFails = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
      printf("FAIL: %s (line %d)\n", (msg), __LINE__); \
      gFails++; \
    } else { \
      printf("ok: %s\n", (msg)); \
    } \
  } while (0)

int main(int argc, char **argv) {
  void *h;
  fn_open pOpen;
  fn_close pClose;
  fn_init pInit;
  fn_digest pDigest;
  haskoki_crypto_ctx_t ctx;
  CK_RV rv;
  CK_BYTE out[64];
  CK_ULONG outLen;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pOpen = (fn_open)dlsym(h, "haskoki_crypto_open");
  pClose = (fn_close)dlsym(h, "haskoki_crypto_close");
  pInit = (fn_init)dlsym(h, "haskoki_crypto_digest_init");
  pDigest = (fn_digest)dlsym(h, "haskoki_crypto_digest");
  CHECK(pOpen && pClose && pInit && pDigest, "trampolines resolve");
  if (gFails) {
    return 1;
  }

  ctx = pOpen();
  CHECK(ctx != NULL, "ctx opens");

  rv = pInit(ctx, 9999, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_SESSION_HANDLE_INVALID, "bad session rejected");

  rv = pInit(ctx, 1, 0x999UL, NULL, 0);
  CHECK(rv == CKR_MECHANISM_INVALID, "bad mechanism rejected");

  /* Digest without init on this ctx (inits above failed cleanly). */
  outLen = sizeof(out);
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_OPERATION_NOT_INITIALIZED, "digest without init rejected");

  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "digest init ok");

  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OPERATION_ACTIVE, "second init is ACTIVE");

  /* Size query. */
  outLen = 0;
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, NULL, &outLen);
  CHECK(rv == CKR_OK && outLen == 32, "size query reports 32");

  /* A successful size query leaves the op live (PKCS#11 v3.1): the
   * follow-up one-shot completes; then re-init, short, recall. */
  outLen = sizeof(out);
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
        "one-shot after query completes with FIPS bytes");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "re-init after one-shot");
  outLen = 8;
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_BUFFER_TOO_SMALL && outLen == 32, "short reports 32");
  /* A second short call re-reports the required length. */
  outLen = 8;
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_BUFFER_TOO_SMALL && outLen == 32, "second short reports 32");
  outLen = sizeof(out);
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
        "recall completes with KAT bytes");
  /* A second size query re-reports the length; the op stays live. */
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "re-init for double query");
  outLen = 0;
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, NULL, &outLen);
  CHECK(rv == CKR_OK && outLen == 32, "first query reports 32");
  outLen = 0;
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, NULL, &outLen);
  CHECK(rv == CKR_OK && outLen == 32, "second query reports 32");
  outLen = sizeof(out);
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
        "one-shot after double query completes");

  /* Fresh one-shot, exact buffer. */
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "init for exact one-shot");
  outLen = sizeof(out);
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECK(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
        "exact one-shot KAT bytes");

  /* NULL length word rejects. */
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "init for null-length probe");
  rv = pDigest(ctx, 1, (CK_BYTE_PTR)"abc", 3, out, NULL);
  CHECK(rv == CKR_ARGUMENTS_BAD, "null length word rejected");

  pClose(ctx);
  dlclose(h);
  if (gFails == 0) {
    printf("PASS: crypto_routed (%s)\n", argv[1]);
  }
  return gFails ? 1 : 0;
}
