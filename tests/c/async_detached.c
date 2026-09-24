/* tests/c/async_detached.c — detach/rejoin C proof (guard page).
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives the detach lifecycle across the
 * real export boundary:
 *
 *   1. Open a process-level store (memory mode) and a context on it.
 *   2. Start an attached digest job into a guard-page buffer (one
 *      mmap()d page, so mprotect() can revoke it exactly).
 *   3. Poll pending (buffer untouched), then GetID -> persistent id.
 *   4. mprotect() the old allocation PROT_NONE: any later touch is a
 *      fatal crash, which fails this test loudly by design.
 *   5. Finalize the provider generation (close the context; the store
 *      and its durable record live outside the provider lifetime).
 *   6. Reinitialize a fresh context on the same store, re-init the
 *      session, and join the persistent id into a NEW buffer.
 *   7. Poll + complete: FIPS 180-4 SHA-256("abc") delivered EXACTLY
 *      ONCE, into the new buffer only.
 *   8. Re-arm the old page read-only and verify its canary is intact:
 *      nothing ever wrote through the revoked binding.
 *
 * Usage: async_detached <path-to-libhaskoki.so>
 * Exit status: 0 iff every check passes.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef CK_BYTE *CK_BYTE_PTR;

typedef struct async_data {
  CK_ULONG ulVersion;
  CK_BYTE_PTR pValue;
  CK_ULONG ulValue;
  CK_ULONG hObject;
  CK_ULONG hAdditionalObject;
} async_data_t;

#define CKR_OK 0x00000000UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_PENDING 0x00000204UL

#define CKM_SHA256 0x00000250UL

#define FN_SIGN 1UL
#define FN_DIGEST 2UL

typedef void *haskoki_async_ctx_t;
typedef void *haskoki_async_job_t;
typedef void *haskoki_async_store_t;
typedef haskoki_async_store_t (*fn_store_open)(const char *path);
typedef void (*fn_store_close)(haskoki_async_store_t *pbox);
typedef haskoki_async_ctx_t (*fn_open_on)(haskoki_async_store_t box);
typedef void (*fn_close)(haskoki_async_ctx_t *pctx);
typedef CK_RV (*fn_init)(haskoki_async_ctx_t ctx, CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_TYPE mech, CK_BYTE_PTR pParams,
                         CK_ULONG ulParamsLen);
typedef CK_RV (*fn_start)(haskoki_async_ctx_t ctx, CK_SESSION_HANDLE hSession,
                          CK_ULONG func, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                          CK_ULONG cap, CK_ULONG ticks,
                          haskoki_async_job_t *pHandle);
typedef CK_RV (*fn_poll)(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                         CK_ULONG func);
typedef CK_RV (*fn_complete)(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                             CK_ULONG func, async_data_t *pResult);
typedef CK_RV (*fn_get_id)(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                           CK_ULONG func, CK_ULONG *pId);
typedef CK_RV (*fn_join)(haskoki_async_ctx_t ctx, CK_ULONG id, CK_ULONG func,
                         CK_SESSION_HANDLE hSession, CK_ULONG cap,
                         haskoki_async_job_t *pHandle, CK_ULONG *pNeed);

/* FIPS 180-4: SHA-256("abc"). */
static const uint8_t kWant[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static int gFails = 0;
static int gPass = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
      printf("FAIL: %s (line %d)\n", (msg), __LINE__); \
      gFails++; \
    } else { \
      printf("ok: %s\n", (msg)); \
      gPass++; \
    } \
  } while (0)

int main(int argc, char **argv) {
  void *h;
  fn_store_open pStoreOpen;
  fn_store_close pStoreClose;
  fn_open_on pOpenOn;
  fn_close pClose;
  fn_init pInit;
  fn_start pStart;
  fn_poll pPoll;
  fn_complete pComplete;
  fn_get_id pGetId;
  fn_join pJoin;
  haskoki_async_store_t store;
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job, job2;
  CK_RV rv;
  CK_ULONG pid, need;
  async_data_t res;
  CK_BYTE buf2[64];
  CK_BYTE *guard;
  const size_t kPage = 4096;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pStoreOpen = (fn_store_open)dlsym(h, "haskoki_async_store_open");
  pStoreClose = (fn_store_close)dlsym(h, "haskoki_async_store_close");
  pOpenOn = (fn_open_on)dlsym(h, "haskoki_async_open_on");
  pClose = (fn_close)dlsym(h, "haskoki_async_close");
  pInit = (fn_init)dlsym(h, "haskoki_async_digest_init");
  pStart = (fn_start)dlsym(h, "haskoki_async_start");
  pPoll = (fn_poll)dlsym(h, "haskoki_async_poll");
  pComplete = (fn_complete)dlsym(h, "haskoki_async_complete");
  pGetId = (fn_get_id)dlsym(h, "haskoki_async_get_id");
  pJoin = (fn_join)dlsym(h, "haskoki_async_join");
  CHECK(pStoreOpen && pStoreClose && pOpenOn && pClose && pInit && pStart &&
        pPoll && pComplete && pGetId && pJoin,
        "trampolines resolve");
  if (gFails) {
    return 1;
  }

  /* Generation 1: store + context + attached job into the guard page. */
  store = pStoreOpen(NULL);
  CHECK(store != NULL, "memory store opens");
  ctx = pOpenOn(store);
  CHECK(ctx != NULL, "ctx opens on the store");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "digest init ok");

  guard = (CK_BYTE *)mmap(NULL, kPage, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(guard != MAP_FAILED, "guard page maps");
  memset(guard, 0xA5, kPage);
  memset(&res, 0xA5, sizeof(res));
  res.pValue = guard;
  res.ulValue = 32;

  job = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 2, &job);
  CHECK(rv == CKR_PENDING && job != NULL, "start reports pending");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_PENDING, "poll pending");
  CHECK(guard[0] == 0xA5 && guard[31] == 0xA5, "pending poll writes nothing");

  /* Detach: the persistent id releases the caller from the old buffer. */
  pid = 0;
  rv = pGetId(ctx, job, FN_DIGEST, &pid);
  CHECK(rv == CKR_OK && pid == 1, "get_id returns persistent id 1");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_ARGUMENTS_BAD, "old handle stale after detach");

  /* Revoke the old allocation. From here, any touch is a fatal crash. */
  if (mprotect(guard, kPage, PROT_NONE) != 0) {
    printf("FAIL: mprotect PROT_NONE failed\n");
    return 1;
  }
  printf("ok: old allocation revoked (PROT_NONE)\n");
  gPass++;

  /* Finalize generation 1; the durable record outlives the provider. */
  pClose(&ctx);
  CHECK(ctx == NULL, "finalize nulls the ctx slot");

  /* Generation 2: reinitialize on the same store, rejoin elsewhere. */
  ctx = pOpenOn(store);
  CHECK(ctx != NULL, "reinit opens on the same store");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "re-init ok");
  job2 = NULL;
  need = 0;
  rv = pJoin(ctx, pid, FN_DIGEST, 1, 32, &job2, &need);
  CHECK(rv == CKR_PENDING && job2 != NULL, "join reports pending");
  /* Freshness here = the old handle is stale (above) while the new
   * one drives and delivers (below). Pointer inequality would be
   * bogus in one process: the RTS may reuse a freed StablePtr slot. */
  printf("note: old handle %p, joined handle %p\n", job, job2);

  memset(&res, 0, sizeof(res));
  memset(buf2, 0xA5, sizeof(buf2));
  res.pValue = buf2;
  res.ulValue = sizeof(buf2);
  rv = pPoll(ctx, job2, FN_DIGEST);
  CHECK(rv == CKR_OK, "joined job ready");
  rv = pComplete(ctx, job2, FN_DIGEST, &res);
  CHECK(rv == CKR_OK && res.ulVersion == 1 && res.ulValue == 32 &&
        memcmp(buf2, kWant, 32) == 0,
        "complete delivers KAT bytes exactly once");
  CHECK(buf2[32] == 0xA5, "new buffer tail canary intact");
  rv = pComplete(ctx, job2, FN_DIGEST, &res);
  CHECK(rv == CKR_ARGUMENTS_BAD, "double complete stale");

  pClose(&ctx);
  CHECK(ctx == NULL, "second finalize nulls the slot");
  pStoreClose(&store);
  CHECK(store == NULL, "store close nulls the slot");

  /* Re-arm the old page read-only: its canary must be intact, proving
   * no write ever went through the revoked binding. (A touch while
   * PROT_NONE would already have crashed above.) */
  if (mprotect(guard, kPage, PROT_READ) != 0) {
    printf("FAIL: mprotect PROT_READ failed\n");
    return 1;
  }
  {
    size_t i;
    int intact = 1;
    for (i = 0; i < kPage; i++) {
      if (guard[i] != 0xA5) {
        intact = 0;
        break;
      }
    }
    CHECK(intact, "revoked page canary intact (never written)");
  }
  munmap(guard, kPage);

  if (gFails) {
    return 1;
  }
  printf("PASS: async_detached (%d checks)\n", gPass);
  return 0;
}
