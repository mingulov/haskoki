/* tests/c/sim_threaded.c — threaded native proof.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives N worker threads through mixed
 * session-churn/digest/event load while one churner thread cycles
 * control token.insert/token.remove. The suite asserts CONSERVATION
 * invariants (stable under scheduling nondeterminism), never
 * interleavings:
 *
 *   * every C_OpenSession the workers count is matched by a
 *     C_CloseSession (per-thread and global opens == closes);
 *   * every call returns a legal code (CKR_OK family, the stale /
 *     contention codes a live module legitimately produces, and
 *     CKR_NO_EVENT for the don't-block polls);
 *   * the process never crashes or hangs, and a final quiet-module
 *     smoke (slot list + open/info/close) succeeds.
 *
 * Any crash, hang (caught by the alarm below), illegal code
 * (notably CKR_GENERAL_ERROR from a caught Haskell exception), or
 * conservation mismatch is a FAIL.
 *
 * Flakiness cuts AGAINST the provider: any observed failure fails the run.
 * Defaults N=4, M=50 (control-churn cycles), ITERS=20000 (worker
 * mixed-op iterations), overridable via HASKOKI_SIM_N/_M/_ITERS.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard). HASKOKI_Control is resolved
 * by dlsym through a locally declared prototype (independent oracle:
 * this TU deliberately does NOT include cbits/haskoki_control.h).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-sim-threaded.sh.
 * Usage: sim_threaded <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Extension entry: local prototype (must match cbits/haskoki_control.h). */
typedef CK_RV (*HASKOKI_Control_fn)(const CK_BYTE_PTR pRequest,
                                    CK_ULONG ulRequestLen,
                                    CK_BYTE_PTR pResponse,
                                    CK_ULONG_PTR pulResponseLen);

#define CONTROL_BUDGET 65536UL

static CK_FUNCTION_LIST_PTR g_f = NULL_PTR;
static HASKOKI_Control_fn g_ctl = NULL;
static atomic_long g_bad = 0;
static atomic_long g_prints = 0;
static atomic_long g_calls = 0;
static atomic_long g_opens = 0;
static atomic_long g_closes = 0;

/* Codes a live module legitimately produces for the hammered
 * entries. Notably absent: CKR_GENERAL_ERROR (the guarded-Haskell
 * tell-tale), CKR_CRYPTOKI_NOT_INITIALIZED (no finalizer thread
 * here — the module stays initialized throughout), and anything
 * else — garbage included. */
static int legal_rv(CK_RV rv) {
  switch (rv) {
  case CKR_OK:
  case CKR_SESSION_HANDLE_INVALID:
  case CKR_OPERATION_ACTIVE:
  case CKR_SESSION_COUNT:
  case CKR_TOKEN_NOT_PRESENT:
  case CKR_SLOT_ID_INVALID:
  case CKR_NO_EVENT:
    return 1;
  default:
    return 0;
  }
}

static void note_rv(const char *what, CK_RV rv) {
  atomic_fetch_add(&g_calls, 1);
  if (!legal_rv(rv)) {
    long n;
    atomic_fetch_add(&g_bad, 1);
    n = atomic_fetch_add(&g_prints, 1);
    if (n < 20) {
      printf("ILLEGAL %s: got 0x%lx\n", what, (unsigned long)rv);
      fflush(stdout);
    }
  }
}

static void note_bad(const char *what, CK_RV rv) {
  long n;
  atomic_fetch_add(&g_bad, 1);
  n = atomic_fetch_add(&g_prints, 1);
  if (n < 20) {
    printf("ILLEGAL %s: got 0x%lx\n", what, (unsigned long)rv);
    fflush(stdout);
  }
}

typedef struct {
  long iters;
  long opens;
  long closes;
} worker_arg_t;

static void *worker_main(void *arg) {
  worker_arg_t *wa = (worker_arg_t *)arg;
  CK_FUNCTION_LIST_PTR f = g_f;
  CK_SESSION_HANDLE sess = 0;
  CK_MECHANISM mech;
  long i;
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  for (i = 0; i < wa->iters; i++) {
    CK_RV rv;
    switch (i % 6) {
    case 0: {
      CK_ULONG n = 0;
      rv = f->C_GetSlotList(CK_TRUE, NULL_PTR, &n);
      note_rv("GetSlotList", rv);
      break;
    }
    case 1: {
      if (sess == 0) {
        CK_SESSION_HANDLE h = 0;
        rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &h);
        note_rv("OpenSession", rv);
        if (rv == CKR_OK) {
          sess = h;
          wa->opens++;
        }
      }
      break;
    }
    case 2: {
      if (sess != 0) {
        CK_SESSION_INFO info;
        rv = f->C_GetSessionInfo(sess, &info);
        note_rv("GetSessionInfo", rv);
        if (rv == CKR_SESSION_HANDLE_INVALID) {
          sess = 0;
        }
      }
      break;
    }
    case 3: {
      /* sess may be 0 here (never opened, or dropped above):
       * HANDLE_INVALID is then the legal answer. */
      rv = f->C_DigestInit(sess, &mech);
      note_rv("DigestInit", rv);
      break;
    }
    case 4: {
      CK_SLOT_ID s = 0xDEADu;
      rv = f->C_WaitForSlotEvent(CKF_DONT_BLOCK, &s, NULL_PTR);
      note_rv("WaitForSlotEvent/nb", rv);
      break;
    }
    case 5: {
      if (sess != 0) {
        rv = f->C_CloseSession(sess);
        note_rv("CloseSession", rv);
        /* Count the close only when the module confirms it; a
         * stale handle was never really ours. */
        if (rv == CKR_OK) {
          wa->closes++;
        }
        sess = 0;
      }
      break;
    }
    }
  }
  /* Thread-end conservation: close any held handle so per-thread
   * opens == closes regardless of where the iteration count lands. */
  if (sess != 0) {
    CK_RV rv = f->C_CloseSession(sess);
    note_rv("CloseSession/end", rv);
    if (rv == CKR_OK) {
      wa->closes++;
    }
    sess = 0;
  }
  atomic_fetch_add(&g_opens, wa->opens);
  atomic_fetch_add(&g_closes, wa->closes);
  if (wa->opens != wa->closes) {
    note_bad("per-thread opens==closes", (CK_RV)(wa->opens - wa->closes));
  }
  return NULL;
}

typedef struct {
  long cycles;
} churner_arg_t;

static CK_RV control_call(const char *req_json) {
  static CK_BYTE resp[CONTROL_BUDGET];
  CK_ULONG len = CONTROL_BUDGET;
  CK_ULONG out_len = 0;
  CK_RV rv = g_ctl((const CK_BYTE_PTR)req_json, (CK_ULONG)strlen(req_json),
                   resp, &len);
  out_len = len;
  (void)out_len;
  return rv;
}

/* Control churner: cycle token.insert/remove on slot 1 (workers live
 * on slot 0) so the event queue, registry, and presence paths churn
 * under the workers' don't-block polls. */
static void *churner_main(void *arg) {
  churner_arg_t *ca = (churner_arg_t *)arg;
  long c;
  for (c = 0; c < ca->cycles; c++) {
    CK_RV rv = control_call("{\"schema_version\":1,\"command\":\"token.insert\","
                            "\"arguments\":{\"slot\":1}}");
    atomic_fetch_add(&g_calls, 1);
    if (rv != CKR_OK) {
      note_bad("control token.insert", rv);
    }
    rv = control_call("{\"schema_version\":1,\"command\":\"token.remove\","
                      "\"arguments\":{\"slot\":1}}");
    atomic_fetch_add(&g_calls, 1);
    if (rv != CKR_OK) {
      note_bad("control token.remove", rv);
    }
  }
  return NULL;
}

static char g_cfg_path[256];

static void write_config(void) {
  /* Test-enabled: the churner issues token.insert/remove mutations. */
  static const char body[] = "schema_version = 1\n"
                             "profile = \"demo-maximal\"\n"
                             "[storage]\n"
                             "kind = \"memory\"\n"
                             "[engine]\n"
                             "kind = \"synthetic\"\n"
                             "[trace]\n"
                             "enabled = false\n"
                             "[control]\n"
                             "enabled = true\n"
                             "test_enabled = true\n";
  char tmpl[] = "/tmp/haskoki-sim-XXXXXX";
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

static long env_long(const char *name, long dflt) {
  const char *v = getenv(name);
  char *end = NULL;
  long n;
  if (v == NULL || *v == '\0') {
    return dflt;
  }
  n = strtol(v, &end, 10);
  if (end == v || n <= 0 || n > 10000000L) {
    return dflt;
  }
  return n;
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f = NULL_PTR;
  CK_RV rv;
  long nworkers;
  long cycles;
  long iters;
  pthread_t *workers;
  worker_arg_t *wargs;
  churner_arg_t carg;
  pthread_t churner;
  long i;
  long bad;
  long calls;
  long opens;
  long closes;
  /* Final-smoke locals. */
  CK_ULONG n = 0;
  CK_SESSION_HANDLE sess = 0;
  CK_SESSION_INFO info;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  nworkers = env_long("HASKOKI_SIM_N", 4);
  cycles = env_long("HASKOKI_SIM_M", 50);
  iters = env_long("HASKOKI_SIM_ITERS", 20000);
  if (nworkers > 64) {
    nworkers = 64;
  }
  printf("sim: N=%ld M=%ld iters=%ld\n", nworkers, cycles, iters);
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (pGetList == NULL) {
    fprintf(stderr, "dlsym C_GetFunctionList failed\n");
    return 2;
  }
  g_ctl = (HASKOKI_Control_fn)dlsym(handle, "HASKOKI_Control");
  if (g_ctl == NULL) {
    fprintf(stderr, "dlsym HASKOKI_Control failed\n");
    return 2;
  }
  rv = pGetList(&f);
  if (rv != CKR_OK || f == NULL_PTR) {
    fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  g_f = f;

  /* Hang guard: a deadlock or stranded waiter fails loudly instead
   * of blocking the driver forever. */
  alarm(180);

  rv = f->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("initial-Initialize", rv);
  }

  workers = (pthread_t *)calloc((size_t)nworkers, sizeof(*workers));
  wargs = (worker_arg_t *)calloc((size_t)nworkers, sizeof(*wargs));
  if (workers == NULL || wargs == NULL) {
    fprintf(stderr, "calloc failed\n");
    return 2;
  }
  for (i = 0; i < nworkers; i++) {
    wargs[i].iters = iters;
    wargs[i].opens = 0;
    wargs[i].closes = 0;
    if (pthread_create(&workers[i], NULL, worker_main, &wargs[i]) != 0) {
      fprintf(stderr, "pthread_create worker failed\n");
      return 2;
    }
  }
  carg.cycles = cycles;
  if (pthread_create(&churner, NULL, churner_main, &carg) != 0) {
    fprintf(stderr, "pthread_create churner failed\n");
    return 2;
  }
  for (i = 0; i < nworkers; i++) {
    pthread_join(workers[i], NULL);
  }
  pthread_join(churner, NULL);
  free(workers);
  free(wargs);

  /* Final quiet-module smoke: slot list + open/info/close. */
  rv = f->C_GetSlotList(CK_FALSE, NULL_PTR, &n);
  if (rv != CKR_OK) {
    note_bad("final-GetSlotList", rv);
  }
  rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                        NULL_PTR, &sess);
  if (rv != CKR_OK || sess == 0) {
    note_bad("final-OpenSession", rv);
  } else {
    rv = f->C_GetSessionInfo(sess, &info);
    if (rv != CKR_OK) {
      note_bad("final-GetSessionInfo", rv);
    }
    rv = f->C_CloseSession(sess);
    if (rv != CKR_OK) {
      note_bad("final-CloseSession", rv);
    }
  }
  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Finalize", rv);
  }

  alarm(0);
  bad = atomic_load(&g_bad);
  calls = atomic_load(&g_calls);
  opens = atomic_load(&g_opens);
  closes = atomic_load(&g_closes);
  printf("SUMMARY: %ld calls, %ld illegal, opens=%ld closes=%ld\n", calls,
         bad, opens, closes);
  if (opens != closes) {
    printf("RESULT: FAIL (global opens %ld != closes %ld)\n", opens, closes);
    return 1;
  }
  if (bad != 0) {
    printf("RESULT: FAIL\n");
    return 1;
  }
  printf("RESULT: PASS\n");
  return 0;
}
