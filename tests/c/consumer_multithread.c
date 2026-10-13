/* tests/c/consumer_multithread.c — distinct-session multithread digest proof.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives N worker threads, released from
 * a common start barrier, through distinct-session SHA-256 digest
 * load. Each worker owns its sessions exclusively: per iteration it
 * opens one session, runs a size-query + one-shot C_Digest and a
 * split multipart C_DigestUpdate/C_DigestFinal over a worker-unique
 * input, and closes the session. The suite asserts per-session
 * isolation invariants (stable under scheduling nondeterminism),
 * never interleavings:
 *
 *   * one-shot and multipart digests of the same input agree on all
 *     32 bytes (full-byte compare, exact length, canary-guarded
 *     output buffers);
 *   * the size query reports 32 and leaves the op live (PKCS#11 v3.1
 *     C_Digest behavior, as the roundtrip consumer proves);
 *   * the sha256("abc") known vector matches its FIPS bytes once, as
 *     an independent oracle besides the self-consistency compares;
 *   * every worker's first digest differs from every other worker's
 *     (unique inputs must digest distinctly — cross-talk would
 *     collide them);
 *   * every C_OpenSession is matched by a C_CloseSession (per-thread
 *     and global opens == closes) and a final quiet-module smoke
 *     (slot list + open/info/close) succeeds.
 *
 * Any crash, hang (caught by the alarm below), return-code surprise,
 * byte mismatch, canary breach, collision, or conservation mismatch
 * is a FAIL. Exit 2 marks a setup failure (module/slot/init), which
 * is never a passing behavior test.
 *
 * Defaults N=4, ITERS=50 (overridable via HASKOKI_MT_N/_ITERS for
 * window tuning; the V4b matrix runs 1/2/4/8 workers and both
 * negotiated mutex modes — this bootstrap leg runs the no-callback
 * mode only). Flakiness cuts AGAINST the provider: any observed
 * failure fails the run.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh,
 * which picks this file up automatically via its consumer_*.c glob.
 * Usage: consumer_multithread <path-to-libhaskoki.so>
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

#define MAX_WORKERS 8
#define DIGEST_LEN 32UL

static const CK_BYTE kSha256Abc[DIGEST_LEN] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static CK_FUNCTION_LIST_PTR g_f = NULL_PTR;
static CK_SLOT_ID g_slot = 0;
static pthread_barrier_t g_start;
static int g_iters = 50;
static atomic_long g_bad = 0;
static atomic_long g_prints = 0;
static atomic_long g_opens = 0;
static atomic_long g_closes = 0;
static CK_BYTE g_first[MAX_WORKERS][DIGEST_LEN];

typedef struct {
  CK_BYTE prefix[16];
  CK_BYTE bytes[64];
  CK_BYTE tail[16];
} Guarded;

static void note_bad(const char *what) {
  long n;
  atomic_fetch_add(&g_bad, 1);
  n = atomic_fetch_add(&g_prints, 1);
  if (n < 20) {
    printf("BAD %s\n", what);
    fflush(stdout);
  }
}

static void guard_init(Guarded *g) {
  memset(g->prefix, 0xa5, sizeof(g->prefix));
  memset(g->bytes, 0x5a, sizeof(g->bytes));
  memset(g->tail, 0xa5, sizeof(g->tail));
}

static int guard_ok(const Guarded *g, CK_ULONG len, const char *what) {
  size_t i;
  for (i = 0; i < sizeof(g->prefix); ++i) {
    if (g->prefix[i] != 0xa5 || g->tail[i] != 0xa5) {
      note_bad(what);
      return 0;
    }
  }
  if (len != DIGEST_LEN) {
    note_bad(what);
    return 0;
  }
  return 1;
}

static void *worker_main(void *arg) {
  long id = (long)arg;
  CK_MECHANISM mech;
  CK_SESSION_HANDLE sess = 0;
  CK_RV rv;
  long opens = 0, closes = 0;
  int iter;
  char detail[160];

  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;

  {
    int brc = pthread_barrier_wait(&g_start);
    if (brc != 0 && brc != PTHREAD_BARRIER_SERIAL_THREAD) {
      note_bad("worker barrier");
      return NULL;
    }
  }

  for (iter = 0; iter < g_iters; ++iter) {
    char input[64];
    int inlen;
    Guarded one, multi;
    CK_ULONG one_len, qlen, multi_len;
    CK_ULONG half;

    inlen = snprintf(input, sizeof(input), "haskoki-mt-%ld-%d", id, iter);
    if (inlen <= 0 || (size_t)inlen >= sizeof(input)) {
      note_bad("worker input format");
      return NULL;
    }

    rv = g_f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK || sess == 0) {
      snprintf(detail, sizeof(detail), "worker %ld open: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      return NULL;
    }
    opens++;

    /* One-shot leg: size query first (reports 32, op stays live). */
    rv = g_f->C_DigestInit(sess, &mech);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld digest-init: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    qlen = 0;
    rv = g_f->C_Digest(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen, NULL_PTR, &qlen);
    if (rv != CKR_OK || qlen != DIGEST_LEN) {
      snprintf(detail, sizeof(detail), "worker %ld size-query: 0x%lx len %lu",
               id, (unsigned long)rv, (unsigned long)qlen);
      note_bad(detail);
      goto close_out;
    }
    guard_init(&one);
    one_len = sizeof(one.bytes);
    rv = g_f->C_Digest(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen, one.bytes, &one_len);
    if (rv != CKR_OK || !guard_ok(&one, one_len, "worker one-shot bytes")) {
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld one-shot: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
      }
      goto close_out;
    }

    /* Multipart leg over the same input, split at an odd point. */
    rv = g_f->C_DigestInit(sess, &mech);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld re-init: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    half = (CK_ULONG)inlen / 2 + 1;
    rv = g_f->C_DigestUpdate(sess, (CK_BYTE_PTR)input, half);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld update-1: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    rv = g_f->C_DigestUpdate(sess, (CK_BYTE_PTR)input + half, (CK_ULONG)inlen - half);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld update-2: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    guard_init(&multi);
    multi_len = sizeof(multi.bytes);
    rv = g_f->C_DigestFinal(sess, multi.bytes, &multi_len);
    if (rv != CKR_OK || !guard_ok(&multi, multi_len, "worker multipart bytes")) {
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld final: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
      }
      goto close_out;
    }
    if (memcmp(one.bytes, multi.bytes, DIGEST_LEN) != 0) {
      snprintf(detail, sizeof(detail), "worker %ld single/multipart mismatch iter %d", id, iter);
      note_bad(detail);
      goto close_out;
    }
    if (iter == 0) {
      memcpy(g_first[id], one.bytes, DIGEST_LEN);
    }

  close_out:
    rv = g_f->C_CloseSession(sess);
    sess = 0;
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld close: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      break;
    }
    closes++;
    if (atomic_load(&g_bad) != 0) {
      break;
    }
  }

  atomic_fetch_add(&g_opens, opens);
  atomic_fetch_add(&g_closes, closes);
  return NULL;
}

static long env_long(const char *name, long dflt, long lo, long hi) {
  const char *text = getenv(name);
  char *end = NULL;
  long val;
  if (text == NULL || *text == '\0') {
    return dflt;
  }
  val = strtol(text, &end, 10);
  if (end == text || *end != '\0' || val < lo || val > hi) {
    return dflt;
  }
  return val;
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f;
  CK_SLOT_ID slots[16];
  CK_ULONG nslots = 16;
  CK_RV rv;
  long nworkers;
  pthread_t workers[MAX_WORKERS];
  long i, j;
  long bad, opens, closes;
  CK_SESSION_HANDLE smoke = 0;
  CK_SESSION_INFO info;
  CK_MECHANISM mech;
  Guarded vec;
  CK_ULONG vec_len;

  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path-to-libhaskoki.so>\n", argv[0]);
    return 2;
  }
  nworkers = env_long("HASKOKI_MT_N", 4, 1, MAX_WORKERS);
  g_iters = (int)env_long("HASKOKI_MT_ITERS", 50, 1, 10000);

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

  /* Hang guard: stranded workers fail loudly instead of blocking join. */
  alarm(300);

  rv = f->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    fprintf(stderr, "C_Initialize failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
  if (rv != CKR_OK || nslots < 1) {
    fprintf(stderr, "no token-present slot: 0x%lx count %lu\n",
            (unsigned long)rv, (unsigned long)nslots);
    return 2;
  }
  g_slot = slots[0];

  /* Independent oracle: the FIPS sha256("abc") vector, once. */
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &smoke);
  if (rv != CKR_OK || smoke == 0) {
    fprintf(stderr, "oracle session failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  atomic_fetch_add(&g_opens, 1);
  rv = f->C_DigestInit(smoke, &mech);
  guard_init(&vec);
  vec_len = sizeof(vec.bytes);
  if (rv == CKR_OK) {
    rv = f->C_Digest(smoke, (CK_BYTE_PTR) "abc", 3, vec.bytes, &vec_len);
  }
  if (rv != CKR_OK || !guard_ok(&vec, vec_len, "oracle bytes") ||
      memcmp(vec.bytes, kSha256Abc, DIGEST_LEN) != 0) {
    printf("BAD oracle vector\n");
    atomic_fetch_add(&g_bad, 1);
  }
  rv = f->C_CloseSession(smoke);
  smoke = 0;
  if (rv != CKR_OK) {
    printf("BAD oracle close: 0x%lx\n", (unsigned long)rv);
    atomic_fetch_add(&g_bad, 1);
  } else {
    atomic_fetch_add(&g_closes, 1);
  }

  if (atomic_load(&g_bad) == 0) {
    if (pthread_barrier_init(&g_start, NULL, (unsigned)nworkers) != 0) {
      fprintf(stderr, "barrier init failed\n");
      return 2;
    }
    for (i = 0; i < nworkers; ++i) {
      if (pthread_create(&workers[i], NULL, worker_main, (void *)i) != 0) {
        fprintf(stderr, "pthread_create worker %ld failed\n", i);
        return 2;
      }
    }
    for (i = 0; i < nworkers; ++i) {
      pthread_join(workers[i], NULL);
    }
    pthread_barrier_destroy(&g_start);
  }

  /* Distinctness: unique inputs must digest distinctly. */
  if (atomic_load(&g_bad) == 0) {
    for (i = 0; i < nworkers; ++i) {
      for (j = i + 1; j < nworkers; ++j) {
        if (memcmp(g_first[i], g_first[j], DIGEST_LEN) == 0) {
          printf("BAD digest collision workers %ld/%ld\n", i, j);
          atomic_fetch_add(&g_bad, 1);
        }
      }
    }
  }

  /* Final quiet-module smoke. */
  if (atomic_load(&g_bad) == 0) {
    rv = f->C_GetSlotList(CK_FALSE, NULL_PTR, &nslots);
    if (rv != CKR_OK) {
      note_bad("final-GetSlotList");
    }
    rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &smoke);
    if (rv == CKR_OK && smoke != 0) {
      atomic_fetch_add(&g_opens, 1);
      rv = f->C_GetSessionInfo(smoke, &info);
      if (rv != CKR_OK) {
        note_bad("final-GetSessionInfo");
      }
      rv = f->C_CloseSession(smoke);
      smoke = 0;
      if (rv == CKR_OK) {
        atomic_fetch_add(&g_closes, 1);
      } else {
        note_bad("final-CloseSession");
      }
    } else {
      note_bad("final-OpenSession");
    }
  }

  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Finalize");
  }

  alarm(0);
  bad = atomic_load(&g_bad);
  opens = atomic_load(&g_opens);
  closes = atomic_load(&g_closes);
  printf("SUMMARY: %ld workers, opens %ld closes %ld, %ld bad\n",
         nworkers, opens, closes, bad);
  if (opens != closes || opens < nworkers + 2) {
    printf("RESULT: FAIL (session conservation: opens %ld closes %ld)\n", opens, closes);
    return 1;
  }
  if (bad != 0) {
    printf("RESULT: FAIL\n");
    return 1;
  }
  printf("RESULT: PASS\n");
  return 0;
}
