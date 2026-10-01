/* Supplementary finalize/wait stress. The C root is atomic and points to a
 * retained liveness cell: after shutdown the empty cell remains rooted, and
 * an old waiter cannot follow a later interval's root. The historical plain
 * pointer comment described a predecessor before that fix.
 *
 * An empty fixture has no event producer: blocking returns only NOT_INITIALIZED;
 * polling returns NO_EVENT or NOT_INITIALIZED, always without writing output.
 * T-N05's internal STM seams prove admission and exact close/claim order. This
 * stress run does not infer admission from a native thread-start acknowledgement.
 *
 * scripts/test-finalize-race.sh runs finalize_race.c, NOT this probe. T-N08's
 * native runner separately compiles/runs this file with 100 cycles.
 * Compile with -Ispec/vendor. Usage: finalize_wait_race_probe MODULE
 * HASKOKI_FINALIZE_WAIT_CYCLES defaults to 50. Crash/timeout is a setup failure.
 */
#define _GNU_SOURCE

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
#include <time.h>
#include <unistd.h>

static CK_FUNCTION_LIST_PTR g_f = NULL_PTR;
static atomic_int g_stop = 0;
static atomic_long g_bad = 0;
static atomic_long g_prints = 0;
static atomic_long g_waits = 0;
static atomic_long g_cycles = 0;

/* Codes the wait/close interplay legitimately produces. Notably
 * absent: CKR_GENERAL_ERROR (the guarded-Haskell tell-tale) and
 * anything else — garbage included. */
static int legal_rv(CK_RV rv, int blocking) {
  return rv == CKR_CRYPTOKI_NOT_INITIALIZED || (!blocking && rv == CKR_NO_EVENT);
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

static void msleep(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;
  nanosleep(&ts, 0);
}

/* Blocking waiter: parks in C_WaitForSlotEvent until C_Finalize wakes
 * it (Haskell queue finalizer), then re-waits. A NOT_INITIALIZED
 * answer between intervals is expected; back off 1ms per miss so the
 * loop never hot-spins the resolve path (the spinner below owns
 * resolve-path pressure, deliberately). */
static void *blocker_main(void *arg) {
  (void)arg;
  while (!atomic_load(&g_stop)) {
    CK_SLOT_ID slot = 0xa5a5a5a5a5a5a5a5UL;
    CK_RV rv = g_f->C_WaitForSlotEvent(0 /* blocking */, &slot, NULL_PTR);
    atomic_fetch_add(&g_waits, 1);
    if (!legal_rv(rv, 1) || slot != 0xa5a5a5a5a5a5a5a5UL) {
      note_bad("blocking-wait", rv);
    }
    if (rv == CKR_CRYPTOKI_NOT_INITIALIZED) {
      msleep(1);
    }
  }
  return NULL;
}

/* Resolve-path spinner: DON'T_BLOCK waits hammer the lock-free
 * g_haskoki_instance resolve while the closer cycles underneath. */
static void *spinner_main(void *arg) {
  (void)arg;
  while (!atomic_load(&g_stop)) {
    CK_SLOT_ID slot = 0xa5a5a5a5a5a5a5a5UL;
    CK_RV rv =
        g_f->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL_PTR);
    atomic_fetch_add(&g_waits, 1);
    if (!legal_rv(rv, 0) || slot != 0xa5a5a5a5a5a5a5a5UL) {
      note_bad("spinner-wait", rv);
    }
  }
  return NULL;
}

typedef struct {
  long cycles;
} closer_arg_t;

/* Close/reopen cycler: the race window is each C_Finalize racing the
 * waiters' lock-free resolve. */
static void *closer_main(void *arg) {
  closer_arg_t *ca = (closer_arg_t *)arg;
  long c;
  for (c = 0; c < ca->cycles; c++) {
    CK_RV rv = g_f->C_Finalize(NULL_PTR);
    if (rv != CKR_OK) {
      note_bad("Finalize", rv);
    }
    rv = g_f->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
      note_bad("Initialize", rv);
    }
    atomic_fetch_add(&g_cycles, 1);
  }
  return NULL;
}

static char g_cfg_path[4096];

static void write_config(void) {
  static const char body[] = "schema_version = 1\n"
                             "profile = \"demo-maximal\"\n"
                             "[storage]\n"
                             "kind = \"memory\"\n"
                             "[engine]\n"
                             "kind = \"synthetic\"\n"
                             "[trace]\n"
                             "enabled = false\n";
  char tmpl[4096];
  const char *scratch = getenv("TMPDIR");
  if (!scratch) scratch = "/tmp";
  if (snprintf(tmpl, sizeof(tmpl), "%s/haskoki-finalize-race-probe-XXXXXX", scratch) >= (int)sizeof(tmpl)) exit(2);
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

static int bounded_join(pthread_t thread) {
  struct timespec until;
  if (clock_gettime(CLOCK_REALTIME, &until)) return -1;
  until.tv_sec += 100;
  return pthread_timedjoin_np(thread, NULL, &until);
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
  long cycles;
  pthread_t blocker;
  pthread_t spinner;
  pthread_t closer;
  closer_arg_t carg;
  long bad;
  long waits;
  long done;
  CK_ULONG n = 0;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  cycles = env_long("HASKOKI_FINALIZE_WAIT_CYCLES", 50);
  printf("race-probe: cycles=%ld\n", cycles);
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

  /* Hang guard: a stranded waiter fails loudly instead of blocking
   * the tally loop forever. */
  alarm(120);

  rv = f->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("initial-Initialize", rv);
  }
  if (pthread_create(&blocker, NULL, blocker_main, NULL) != 0 ||
      pthread_create(&spinner, NULL, spinner_main, NULL) != 0) {
    fprintf(stderr, "pthread_create waiter failed\n");
    return 2;
  }
  carg.cycles = cycles;
  if (pthread_create(&closer, NULL, closer_main, &carg) != 0) {
    fprintf(stderr, "pthread_create closer failed\n");
    return 2;
  }
  if (bounded_join(closer)) return 2;
  /* Stop the waiters: C_Finalize wakes the parked blocker (Haskell
   * queue finalizer); the spinner observes the flag directly. */
  atomic_store(&g_stop, 1);
  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("stop-Finalize", rv);
  }
  if (bounded_join(blocker)) return 2;
  if (bounded_join(spinner)) return 2;

  /* Final quiet-module smoke. */
  rv = f->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Initialize", rv);
  }
  rv = f->C_GetSlotList(CK_FALSE, NULL_PTR, &n);
  if (rv != CKR_OK) {
    note_bad("final-GetSlotList", rv);
  }
  CK_SLOT_ID empty = 0xa5a5a5a5a5a5a5a5UL;
  rv = f->C_WaitForSlotEvent(CKF_DONT_BLOCK, &empty, NULL_PTR);
  if (rv != CKR_NO_EVENT || empty != 0xa5a5a5a5a5a5a5a5UL) note_bad("final-empty-poll", rv);
  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Finalize", rv);
  }

  alarm(0);
  bad = atomic_load(&g_bad);
  waits = atomic_load(&g_waits);
  done = atomic_load(&g_cycles);
  printf("SUMMARY: %ld cycles, %ld waits, %ld illegal\n", done, waits, bad);
  if (done != cycles) {
    printf("RESULT: FAIL (short cycle count)\n");
    return 1;
  }
  if (bad != 0) {
    printf("RESULT: FAIL\n");
    return 1;
  }
  unlink(g_cfg_path);
  printf("RESULT: PASS (unexplained_ok=0 canary=pass)\n");
  return 0;
}
