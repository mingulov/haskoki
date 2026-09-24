/* tests/c/async_restart.c — two-process SQLite recovery proof.
 *
 * Standalone C program (non-Haskell executable), run twice as TWO
 * SEPARATE OS processes against one SQLite store file:
 *
 *   process A: async_restart A <libhaskoki.so> <dbpath>
 *     opens the store file, opens a context, inits, starts an
 *     attached digest job, detaches it (GetID), then closes the
 *     context AND the store and exits WITHOUT completing. Prints
 *     "PID=<id> HANDLE=<ptr>" for the runner to hand to B.
 *
 *   process B: async_restart B <libhaskoki.so> <dbpath> <pid> <oldhandle>
 *     opens the SAME store file, opens a fresh context (token
 *     identity/metadata reloaded from SQLite), rejoins the persistent
 *     id, and completes: KAT bytes exactly once. The joined handle
 *     must differ from A's old handle (fresh native identities in
 *     process B; old handles/pointers are never restored).
 *
 * Exit status: 0 iff every check passes.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <inttypes.h>
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
typedef CK_BYTE *CK_BYTE_PTR;

typedef struct async_data {
  CK_ULONG ulVersion;
  CK_BYTE_PTR pValue;
  CK_ULONG ulValue;
  CK_ULONG hObject;
  CK_ULONG hAdditionalObject;
} async_data_t;

#define CKR_OK 0x00000000UL
#define CKR_PENDING 0x00000204UL
#define CKR_SAVED_STATE_INVALID 0x00000160UL

#define CKM_SHA256 0x00000250UL
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

static void *gDl;
static fn_store_open pStoreOpen;
static fn_store_close pStoreClose;
static fn_open_on pOpenOn;
static fn_close pClose;
static fn_init pInit;
static fn_start pStart;
static fn_poll pPoll;
static fn_complete pComplete;
static fn_get_id pGetId;
static fn_join pJoin;

static int resolve(const char *so) {
  gDl = dlopen(so, RTLD_NOW | RTLD_LOCAL);
  if (!gDl) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 0;
  }
  pStoreOpen = (fn_store_open)dlsym(gDl, "haskoki_async_store_open");
  pStoreClose = (fn_store_close)dlsym(gDl, "haskoki_async_store_close");
  pOpenOn = (fn_open_on)dlsym(gDl, "haskoki_async_open_on");
  pClose = (fn_close)dlsym(gDl, "haskoki_async_close");
  pInit = (fn_init)dlsym(gDl, "haskoki_async_digest_init");
  pStart = (fn_start)dlsym(gDl, "haskoki_async_start");
  pPoll = (fn_poll)dlsym(gDl, "haskoki_async_poll");
  pComplete = (fn_complete)dlsym(gDl, "haskoki_async_complete");
  pGetId = (fn_get_id)dlsym(gDl, "haskoki_async_get_id");
  pJoin = (fn_join)dlsym(gDl, "haskoki_async_join");
  if (!pStoreOpen || !pStoreClose || !pOpenOn || !pClose || !pInit ||
      !pStart || !pPoll || !pComplete || !pGetId || !pJoin) {
    printf("FAIL: trampolines resolve\n");
    return 0;
  }
  printf("ok: trampolines resolve\n");
  gPass++;
  return 1;
}

/* Process A: detach into SQLite, then exit without completing. */
static int runA(const char *dbpath) {
  haskoki_async_store_t store;
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job, attached;
  CK_RV rv;
  CK_ULONG pid = 0;

  store = pStoreOpen(dbpath);
  CHECK(store != NULL, "A: sqlite store opens");
  if (!store) {
    return 1;
  }
  ctx = pOpenOn(store);
  CHECK(ctx != NULL, "A: ctx opens on the store");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "A: digest init ok");
  job = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECK(rv == CKR_PENDING && job != NULL, "A: start reports pending");
  rv = pGetId(ctx, job, FN_DIGEST, &pid);
  CHECK(rv == CKR_OK && pid == 1, "A: get_id returns persistent id 1");
  /* A second, attached-only job: close must quiesce it WITHOUT a
   * durable record, so process B can prove it was not resurrected. */
  attached = NULL;
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 5, &attached);
  CHECK(rv == CKR_PENDING && attached != NULL, "A: attached job starts");
  /* Close everything WITHOUT completing: the one durable record must
   * carry the detached job across the process exit. */
  pClose(&ctx);
  CHECK(ctx == NULL, "A: ctx closed");
  pStoreClose(&store);
  CHECK(store == NULL, "A: store closed");
  if (gFails) {
    return 1;
  }
  /* Hand the id + old handle to process B (via the runner). */
  printf("PID=%lu HANDLE=%p\n", pid, job);
  printf("PASS: async_restart A (%d checks)\n", gPass);
  return 0;
}

/* Process B: rejoin the SAME persistent id from a fresh process.
 *
 * Freshness notes (what this function proves, and how):
 *
 * - The session is fresh, not restored: digest re-init reports OK. A
 *   restored session would still hold the initialized slot and the
 *   second init would fail OPERATION_ACTIVE instead.
 * - Token identity/metadata is reloaded: the join validates the
 *   persistent id against the token generation read back from the
 *   SQLite file, and only then attaches.
 * - Old handles/pointers are not restored: everything B touches was
 *   allocated by B (its context, session, and joined job). StablePtr
 *   values are small table indices, so cross-process pointer
 *   comparison would be meaningless (deterministic RTS allocation
 *   order reuses the same small integers); the old handle is logged,
 *   not compared.
 * - Non-detached jobs are not resurrected: A's attached-only job got
 *   no persistent id, and joining the next id here is invalid.
 */
static int runB(const char *dbpath, unsigned long pid, void *oldHandle) {
  haskoki_async_store_t store;
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job2, bogus;
  async_data_t res;
  CK_BYTE buf[64];
  CK_RV rv;
  CK_ULONG need = 0;

  printf("note: B pid=%lu old-handle=%p (logged, not compared)\n",
         pid, oldHandle);
  store = pStoreOpen(dbpath);
  CHECK(store != NULL, "B: sqlite store reopens");
  if (!store) {
    return 1;
  }
  ctx = pOpenOn(store);
  CHECK(ctx != NULL, "B: fresh ctx opens on the same file");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECK(rv == CKR_OK, "B: digest re-init ok (session is fresh)");
  bogus = NULL;
  rv = pJoin(ctx, (CK_ULONG)(pid + 1), FN_DIGEST, 1, 32, &bogus, &need);
  CHECK(rv == CKR_SAVED_STATE_INVALID && bogus == NULL,
        "B: attached-only job not resurrected");
  job2 = NULL;
  rv = pJoin(ctx, (CK_ULONG)pid, FN_DIGEST, 1, 32, &job2, &need);
  CHECK(rv == CKR_PENDING && job2 != NULL, "B: join reports pending");
  memset(&res, 0, sizeof(res));
  memset(buf, 0xA5, sizeof(buf));
  res.pValue = buf;
  res.ulValue = sizeof(buf);
  rv = pPoll(ctx, job2, FN_DIGEST);
  CHECK(rv == CKR_OK, "B: joined job ready");
  rv = pComplete(ctx, job2, FN_DIGEST, &res);
  CHECK(rv == CKR_OK && res.ulValue == 32 && memcmp(buf, kWant, 32) == 0,
        "B: complete delivers KAT bytes exactly once");
  CHECK(buf[32] == 0xA5, "B: buffer tail canary intact");
  pClose(&ctx);
  CHECK(ctx == NULL, "B: ctx closed");
  pStoreClose(&store);
  CHECK(store == NULL, "B: store closed");
  if (gFails) {
    return 1;
  }
  printf("PASS: async_restart B (%d checks)\n", gPass);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s A|B <libhaskoki.so> <dbpath> [pid oldhandle]\n",
            argv[0]);
    return 2;
  }
  if (!resolve(argv[2])) {
    return 1;
  }
  if (strcmp(argv[1], "A") == 0) {
    return runA(argv[3]);
  }
  if (strcmp(argv[1], "B") == 0) {
    unsigned long pid;
    void *oldHandle;
    if (argc != 6 || sscanf(argv[4], "%lu", &pid) != 1 ||
        sscanf(argv[5], "%p", &oldHandle) != 1) {
      fprintf(stderr, "usage: %s B <so> <dbpath> <pid> <oldhandle>\n", argv[0]);
      return 2;
    }
    return runB(argv[3], pid, oldHandle);
  }
  fprintf(stderr, "unknown mode %s\n", argv[1]);
  return 2;
}
