/* tests/c/finalize_race.c — finalize-vs-entrant race probe.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and hammers it with N worker threads
 * looping cheap routed entries (C_GetSlotList, C_GetSessionInfo on a
 * real session, C_DigestInit) while one finalizer thread loops
 * C_Initialize/C_Finalize M times.
 *
 * Pass criteria: every call returns a legal code (CKR_OK family,
 * CKR_CRYPTOKI_NOT_INITIALIZED, or the stale-handle/contention codes
 * a cycling instance legitimately produces), the process never
 * crashes or hangs, and a final C_Initialize + smoke entry succeeds.
 * Any crash, hang (caught by the alarm below), or illegal code
 * (notably CKR_GENERAL_ERROR from a caught Haskell exception, or
 * garbage from use-after-shutdown) is a FAIL.
 *
 * Flakiness cuts AGAINST the provider: any observed failure fails the run.
 * Defaults N=4, M=50 (overridable via HASKOKI_RACE_N/_M/_ITERS for
 * window tuning); worker iterations default high enough to outlast
 * the finalizer so contention covers every cycle.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-finalize-race.sh.
 * Usage: finalize_race <path-to-libhaskoki.so>
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

static CK_FUNCTION_LIST_PTR g_f = NULL_PTR;
static atomic_long g_bad = 0;
static atomic_long g_prints = 0;
static atomic_long g_calls = 0;

/* Codes a cycling instance legitimately produces for the hammered
 * entries. Notably absent: CKR_GENERAL_ERROR (the guarded-Haskell
 * tell-tale) and anything else — garbage included. */
static int legal_rv(CK_RV rv) {
  switch (rv) {
  case CKR_OK:
  case CKR_CRYPTOKI_NOT_INITIALIZED:
  case CKR_SESSION_HANDLE_INVALID:
  case CKR_OPERATION_ACTIVE:
  case CKR_SESSION_COUNT:
  case CKR_TOKEN_NOT_PRESENT:
  case CKR_SLOT_ID_INVALID:
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
    CK_ULONG n = 0;
    CK_SESSION_INFO info;
    rv = f->C_GetSlotList(CK_TRUE, NULL_PTR, &n);
    note_rv("GetSlotList", rv);
    if (sess == 0) {
      CK_SESSION_HANDLE h = 0;
      rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                            NULL_PTR, &h);
      note_rv("OpenSession", rv);
      if (rv == CKR_OK) {
        sess = h;
      }
    } else {
      rv = f->C_GetSessionInfo(sess, &info);
      note_rv("GetSessionInfo", rv);
      if (rv == CKR_SESSION_HANDLE_INVALID ||
          rv == CKR_CRYPTOKI_NOT_INITIALIZED) {
        sess = 0;
      }
    }
    /* sess may be 0 here (stale above, or never opened while the
     * finalizer cycles): HANDLE_INVALID is then the legal answer. */
    rv = f->C_DigestInit(sess, &mech);
    note_rv("DigestInit", rv);
  }
  return NULL;
}

typedef struct {
  long cycles;
} finalizer_arg_t;

static void *finalizer_main(void *arg) {
  finalizer_arg_t *fa = (finalizer_arg_t *)arg;
  CK_FUNCTION_LIST_PTR f = g_f;
  long m;
  for (m = 0; m < fa->cycles; m++) {
    CK_RV rv;
    rv = f->C_Initialize(NULL_PTR);
    atomic_fetch_add(&g_calls, 1);
    if (rv != CKR_OK) {
      note_bad("Initialize", rv);
    }
    rv = f->C_Finalize(NULL_PTR);
    atomic_fetch_add(&g_calls, 1);
    if (rv != CKR_OK) {
      note_bad("Finalize", rv);
    }
  }
  return NULL;
}

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
  char tmpl[] = "/tmp/haskoki-finalize-race-XXXXXX";
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
  worker_arg_t warg;
  finalizer_arg_t farg;
  pthread_t finalizer;
  long i;
  long bad;
  long calls;
  /* Final-smoke locals. */
  CK_ULONG n = 0;
  CK_SESSION_HANDLE sess = 0;
  CK_SESSION_INFO info;
  CK_MECHANISM mech;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  nworkers = env_long("HASKOKI_RACE_N", 4);
  cycles = env_long("HASKOKI_RACE_M", 50);
  iters = env_long("HASKOKI_RACE_ITERS", 100000);
  if (nworkers > 64) {
    nworkers = 64;
  }
  printf("race: N=%ld M=%ld iters=%ld\n", nworkers, cycles, iters);
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
  rv = pGetList(&f);
  if (rv != CKR_OK || f == NULL_PTR) {
    fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  g_f = f;

  /* Hang guard: a deadlock or stranded waiter fails loudly instead
   * of blocking the driver forever. */
  alarm(180);

  workers = (pthread_t *)calloc((size_t)nworkers, sizeof(*workers));
  if (workers == NULL) {
    fprintf(stderr, "calloc failed\n");
    return 2;
  }
  warg.iters = iters;
  for (i = 0; i < nworkers; i++) {
    if (pthread_create(&workers[i], NULL, worker_main, &warg) != 0) {
      fprintf(stderr, "pthread_create worker failed\n");
      return 2;
    }
  }
  farg.cycles = cycles;
  if (pthread_create(&finalizer, NULL, finalizer_main, &farg) != 0) {
    fprintf(stderr, "pthread_create finalizer failed\n");
    return 2;
  }
  for (i = 0; i < nworkers; i++) {
    pthread_join(workers[i], NULL);
  }
  pthread_join(finalizer, NULL);
  free(workers);

  /* Final C_Initialize + smoke entry must succeed on the quiet
   * module (all hammering joined above). */
  rv = f->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Initialize", rv);
  }
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
    mech.mechanism = CKM_SHA256;
    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;
    rv = f->C_DigestInit(sess, &mech);
    if (rv != CKR_OK) {
      note_bad("final-DigestInit", rv);
    }
  }
  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Finalize", rv);
  }

  alarm(0);
  bad = atomic_load(&g_bad);
  calls = atomic_load(&g_calls);
  printf("SUMMARY: %ld calls, %ld illegal\n", calls, bad);
  if (bad != 0) {
    printf("RESULT: FAIL\n");
    return 1;
  }
  printf("RESULT: PASS\n");
  return 0;
}
