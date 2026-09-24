/* tests/c/async_attached.c — attached-async C proof.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module, resolves the async trampolines
 * (haskoki_async_* in cbits/exports.c), and drives attached digest
 * jobs across the real export boundary: pending polls leave canary
 * result storage untouched, completion delivers FIPS 180-4
 * SHA-256("abc") exactly once, wrong-function/cancel/refusal paths
 * follow the typed contract, and close drains through the handle
 * slot (idempotent, nulled).
 *
 * Usage: async_attached <path-to-libhaskoki.so>
 * Exit status: 0 iff every check passes.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stddef.h>
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
typedef unsigned long CK_OBJECT_HANDLE;

/* Pinned CK_ASYNC_DATA mirror (layout pinned by tests/c/layout_320.c). */
typedef struct async_data {
  CK_ULONG ulVersion;
  CK_BYTE_PTR pValue;
  CK_ULONG ulValue;
  CK_OBJECT_HANDLE hObject;
  CK_OBJECT_HANDLE hAdditionalObject;
} async_data_t;

#define CKR_OK 0x00000000UL
#define CKR_HOST_MEMORY 0x00000002UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_PENDING 0x00000204UL

#define CKM_SHA256 0x00000250UL

#define FN_SIGN 1UL
#define FN_DIGEST 2UL

typedef void *haskoki_async_ctx_t;
typedef void *haskoki_async_job_t;
typedef haskoki_async_ctx_t (*fn_open)(void);
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
typedef CK_RV (*fn_cancel)(haskoki_async_ctx_t ctx, haskoki_async_job_t job);

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

static void fill_canary(void *p, size_t n) {
  memset(p, 0xA5, n);
}

static int is_canary(const void *p, size_t n) {
  const unsigned char *b = (const unsigned char *)p;
  size_t i;
  for (i = 0; i < n; i++) {
    if (b[i] != 0xA5) {
      return 0;
    }
  }
  return 1;
}

/* Struct canary with the live pValue/ulValue fields masked out. */
static int struct_canary_intact(const async_data_t *r) {
  unsigned char raw[sizeof(*r)];
  memcpy(raw, r, sizeof(raw));
  memset(raw + offsetof(async_data_t, pValue), 0xA5, sizeof(r->pValue));
  memset(raw + offsetof(async_data_t, ulValue), 0xA5, sizeof(r->ulValue));
  return is_canary(raw, sizeof(raw));
}

int main(int argc, char **argv) {
  void *h;
  fn_open pOpen;
  fn_close pClose;
  fn_init pInit;
  fn_start pStart;
  fn_poll pPoll;
  fn_complete pComplete;
  fn_cancel pCancel;
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job;
  CK_RV rv;
  async_data_t res;
  CK_BYTE buf[64];

  _Static_assert(sizeof(async_data_t) == 40, "async result size");
  _Static_assert(offsetof(async_data_t, ulVersion) == 0, "async.version");
  _Static_assert(offsetof(async_data_t, pValue) == 8, "async.value");
  _Static_assert(offsetof(async_data_t, ulValue) == 16, "async.valuelen");
  _Static_assert(offsetof(async_data_t, hObject) == 24, "async.object");
  _Static_assert(offsetof(async_data_t, hAdditionalObject) == 32, "async.object2");

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pOpen = (fn_open)dlsym(h, "haskoki_async_open");
  pClose = (fn_close)dlsym(h, "haskoki_async_close");
  pInit = (fn_init)dlsym(h, "haskoki_async_digest_init");
  pStart = (fn_start)dlsym(h, "haskoki_async_start");
  pPoll = (fn_poll)dlsym(h, "haskoki_async_poll");
  pComplete = (fn_complete)dlsym(h, "haskoki_async_complete");
  pCancel = (fn_cancel)dlsym(h, "haskoki_async_cancel");
  CHECK(pOpen && pClose && pInit && pStart && pPoll && pComplete && pCancel,
        "trampolines resolve");
  if (gFails) {
    return 1;
  }

  ctx = pOpen();
  CHECK(ctx != NULL, "ctx opens");

  /* Refusals before init: typed codes, null handles, no jobs. */
  job = (haskoki_async_job_t)(uintptr_t)0xDEAD;
  rv = pStart(ctx, 1, FN_SIGN, (CK_BYTE_PTR)"abc", 3, 64, 1, &job);
  CHECK(rv == CKR_OPERATION_NOT_INITIALIZED && job == NULL,
        "uninit sign start refused");
  rv = pStart(ctx, 1, 99, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECK(rv == CKR_ARGUMENTS_BAD && job == NULL, "bad function refused");
  rv = pStart(ctx, 9999, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECK(rv == CKR_SESSION_HANDLE_INVALID && job == NULL, "bad session refused");

  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "digest init ok");

  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 0, 1, &job);
  CHECK(rv == CKR_ARGUMENTS_BAD && job == NULL, "zero cap refused");

  /* The main flow: pending polls keep canaries, delivery is exact. */
  job = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 2, &job);
  CHECK(rv == CKR_PENDING && job != NULL, "start reports pending");
  fill_canary(&res, sizeof(res));
  fill_canary(buf, sizeof(buf));
  res.pValue = buf;
  res.ulValue = 32;
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_PENDING, "poll 1 pending");
  CHECK(struct_canary_intact(&res), "poll-pending struct intact");
  CHECK(is_canary(buf, sizeof(buf)), "poll-pending buffer intact");
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_PENDING, "complete-while-pending");
  CHECK(struct_canary_intact(&res), "pending-complete struct intact");
  CHECK(is_canary(buf, sizeof(buf)), "pending-complete buffer intact");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_OK, "poll 2 ready");
  CHECK(struct_canary_intact(&res), "drive writes nothing");
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_OK && res.ulVersion == 1 && res.ulValue == 32 &&
        res.hObject == 0 && res.hAdditionalObject == 0 &&
        memcmp(buf, kWant, 32) == 0,
        "complete delivers KAT bytes exactly");
  CHECK(is_canary(buf + 32, sizeof(buf) - 32), "buffer tail canary intact");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_ARGUMENTS_BAD, "poll-after-deliver stale");
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_ARGUMENTS_BAD, "double complete stale");

  /* Wrong function: refused, job intact, correct flow delivers. */
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "re-init for second job");
  job = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECK(rv == CKR_PENDING && job != NULL, "second job starts");
  rv = pPoll(ctx, job, FN_SIGN);
  CHECK(rv == CKR_ARGUMENTS_BAD, "wrong poller refused");
  fill_canary(&res, sizeof(res));
  fill_canary(buf, sizeof(buf));
  res.pValue = buf;
  res.ulValue = 32;
  rv = pComplete(ctx, job, FN_SIGN, &res);
  CHECK(rv == CKR_ARGUMENTS_BAD, "wrong completer refused");
  CHECK(struct_canary_intact(&res), "wrong-complete struct intact");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_OK, "correct poll ready after refusal");
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_OK && memcmp(buf, kWant, 32) == 0,
        "correct complete delivers after refusal");

  /* Cancel: terminal, freed; late use is stale and silent. */
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "re-init for third job");
  job = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 5, &job);
  CHECK(rv == CKR_PENDING && job != NULL, "third job starts");
  rv = pCancel(ctx, job);
  CHECK(rv == CKR_OK, "cancel ok");
  fill_canary(&res, sizeof(res));
  fill_canary(buf, sizeof(buf));
  res.pValue = buf;
  res.ulValue = 32;
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_ARGUMENTS_BAD, "complete-after-cancel stale");
  CHECK(struct_canary_intact(&res), "cancelled struct intact");
  CHECK(is_canary(buf, sizeof(buf)), "cancelled buffer intact");

  /* Short complete sizes with the job held; retry delivers. The
   * canceled third job never consumed its init, so none is needed. */
  job = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECK(rv == CKR_PENDING && job != NULL, "fourth job starts");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECK(rv == CKR_OK, "fourth job ready");
  fill_canary(&res, sizeof(res));
  fill_canary(buf, sizeof(buf));
  res.pValue = buf;
  res.ulValue = 8;
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_BUFFER_TOO_SMALL && res.ulValue == 32,
        "short complete sizes");
  CHECK(is_canary(buf, sizeof(buf)), "short buffer intact");
  res.ulValue = 32;
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECK(rv == CKR_OK && memcmp(buf, kWant, 32) == 0, "retry delivers");

  /* Fill the table: 8 live; the 9th refuses host-memory. */
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "re-init for fill");
  {
    haskoki_async_job_t jobs[8];
    int i;
    int allPending = 1;
    for (i = 0; i < 8; i++) {
      jobs[i] = NULL;
      rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 5, &jobs[i]);
      if (rv != CKR_PENDING || jobs[i] == NULL) {
        allPending = 0;
      }
    }
    CHECK(allPending, "8 jobs fill the table");
    (void)jobs;
    job = (haskoki_async_job_t)(uintptr_t)0xDEAD;
    rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
    CHECK(rv == CKR_HOST_MEMORY && job == NULL, "9th start host-memory");
  }

  /* Close drains through the slot: idempotent and nulled. */
  pClose(&ctx);
  CHECK(ctx == NULL, "close nulls the slot");
  pClose(&ctx);
  CHECK(ctx == NULL, "double close silent");

  if (gFails) {
    return 1;
  }
  printf("PASS: async_attached (%d checks)\n", gPass);
  return 0;
}
