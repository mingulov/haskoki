/* tests/c/mutexes.c — callback-lock canary (standalone).
 *
 * Counts application mutex-callback create/use/destroy traffic across
 * simulated provider init/use/finalize intervals, including
 * partial-initialization cleanup: when lock provisioning fails at
 * step k, every previously created mutex must be destroyed exactly
 * once and no further callbacks may fire.
 *
 * Compiled against the pinned 3.2 headers ONLY
 * (spec/vendor): compile with -I spec/vendor.
 * Part of scripts/test-c-mutexes.sh. Exit status 0 iff all checks pass.
 */

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#include "pkcs11.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static int g_failures = 0;

#define EXPECT_EQ(actual, expected, what) do { \
    long _a = (long)(actual); \
    long _e = (long)(expected); \
    if (_a != _e) { \
      printf("FAIL: %s: got %ld, want %ld\n", (what), _a, _e); \
      g_failures++; \
    } \
  } while (0)

/* ---------- counting callback fixtures (pthread-backed) ---------- */

static long g_created = 0;
static long g_destroyed = 0;
static long g_locked = 0;
static long g_unlocked = 0;
/* Fail the Nth creation (1-based); 0 disables failure injection. */
static long g_fail_at = 0;

static void mu_reset(void) {
  g_created = 0;
  g_destroyed = 0;
  g_locked = 0;
  g_unlocked = 0;
  g_fail_at = 0;
}

static CK_RV mu_create(CK_VOID_PTR_PTR pp) {
  pthread_mutex_t *m;
  if (pp == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  if (g_fail_at > 0 && g_created + 1 == g_fail_at) {
    return CKR_GENERAL_ERROR;
  }
  m = malloc(sizeof(*m));
  if (m == NULL) {
    return CKR_GENERAL_ERROR;
  }
  pthread_mutex_init(m, NULL);
  *pp = m;
  g_created++;
  return CKR_OK;
}

static CK_RV mu_destroy(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  pthread_mutex_destroy((pthread_mutex_t *)p);
  free(p);
  g_destroyed++;
  return CKR_OK;
}

static CK_RV mu_lock(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  pthread_mutex_lock((pthread_mutex_t *)p);
  g_locked++;
  return CKR_OK;
}

static CK_RV mu_unlock(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  g_unlocked++;
  pthread_mutex_unlock((pthread_mutex_t *)p);
  return CKR_OK;
}

static CK_CREATEMUTEX g_create = mu_create;
static CK_DESTROYMUTEX g_destroy = mu_destroy;
static CK_LOCKMUTEX g_lock = mu_lock;
static CK_UNLOCKMUTEX g_unlock = mu_unlock;

/* ---------- simulated provider init/use/finalize ---------- */

#define MAX_LOCKS 8

typedef struct {
  CK_VOID_PTR locks[MAX_LOCKS];
  int nlocks;
} provider_t;

/* Provision n locks; on any creation failure destroy what was
 * created and report the failure (partial-init cleanup). */
static CK_RV provider_init(provider_t *p, int n) {
  int i;
  p->nlocks = 0;
  for (i = 0; i < MAX_LOCKS; i++) {
    p->locks[i] = NULL;
  }
  for (i = 0; i < n; i++) {
    CK_RV rv = g_create(&p->locks[i]);
    if (rv != CKR_OK) {
      int j;
      for (j = i - 1; j >= 0; j--) {
        g_destroy(p->locks[j]);
        p->locks[j] = NULL;
      }
      p->nlocks = 0;
      return rv;
    }
    p->nlocks++;
  }
  return CKR_OK;
}

/* Use each lock once around a trivial critical section. */
static void provider_use(provider_t *p) {
  int i;
  for (i = 0; i < p->nlocks; i++) {
    g_lock(p->locks[i]);
    g_unlock(p->locks[i]);
  }
}

static CK_RV provider_finalize(provider_t *p) {
  int i;
  for (i = p->nlocks - 1; i >= 0; i--) {
    g_destroy(p->locks[i]);
    p->locks[i] = NULL;
  }
  p->nlocks = 0;
  return CKR_OK;
}

/* ---------- cases ---------- */

static void case_clean_interval(void) {
  provider_t p;
  CK_RV rv;
  printf("case: clean init/use/finalize\n");
  mu_reset();
  rv = provider_init(&p, 3);
  EXPECT_EQ(rv, CKR_OK, "init rv");
  EXPECT_EQ(g_created, 3, "created");
  provider_use(&p);
  provider_use(&p);
  EXPECT_EQ(g_locked, 6, "locks");
  EXPECT_EQ(g_unlocked, 6, "unlocks");
  rv = provider_finalize(&p);
  EXPECT_EQ(rv, CKR_OK, "finalize rv");
  EXPECT_EQ(g_destroyed, 3, "destroyed");
  EXPECT_EQ(g_created - g_destroyed, 0, "no leaks");
}

static void case_partial_cleanup_at(int fail_at, int n) {
  provider_t p;
  CK_RV rv;
  char what[128];
  printf("case: partial-init cleanup (fail at %d of %d)\n", fail_at, n);
  mu_reset();
  g_fail_at = fail_at;
  rv = provider_init(&p, n);
  snprintf(what, sizeof(what), "init rv (fail at %d)", fail_at);
  EXPECT_EQ(rv, CKR_GENERAL_ERROR, what);
  /* fail_at creations attempted, fail_at - 1 succeeded, all destroyed. */
  snprintf(what, sizeof(what), "created (fail at %d)", fail_at);
  EXPECT_EQ(g_created, fail_at - 1, what);
  snprintf(what, sizeof(what), "destroyed (fail at %d)", fail_at);
  EXPECT_EQ(g_destroyed, fail_at - 1, what);
  snprintf(what, sizeof(what), "no live locks (fail at %d)", fail_at);
  EXPECT_EQ(p.nlocks, 0, what);
  snprintf(what, sizeof(what), "no use after failed init (fail at %d)", fail_at);
  EXPECT_EQ(g_locked + g_unlocked, 0, what);
  /* Finalize after failed init destroys nothing further. */
  rv = provider_finalize(&p);
  snprintf(what, sizeof(what), "finalize rv (fail at %d)", fail_at);
  EXPECT_EQ(rv, CKR_OK, what);
  snprintf(what, sizeof(what), "destroyed unchanged (fail at %d)", fail_at);
  EXPECT_EQ(g_destroyed, fail_at - 1, what);
}

static void case_null_guards(void) {
  printf("case: null guards\n");
  mu_reset();
  EXPECT_EQ(mu_create(NULL), CKR_ARGUMENTS_BAD, "create null");
  EXPECT_EQ(mu_destroy(NULL), CKR_ARGUMENTS_BAD, "destroy null");
  EXPECT_EQ(mu_lock(NULL), CKR_ARGUMENTS_BAD, "lock null");
  EXPECT_EQ(mu_unlock(NULL), CKR_ARGUMENTS_BAD, "unlock null");
  EXPECT_EQ(g_created + g_destroyed + g_locked + g_unlocked, 0,
            "no counts on null");
}

int main(void) {
  int k;
  case_clean_interval();
  for (k = 1; k <= 4; k++) {
    case_partial_cleanup_at(k, 4);
  }
  case_null_guards();
  if (g_failures == 0) {
    printf("PASS: mutexes (create/use/destroy + partial cleanup)\n");
    return 0;
  }
  printf("FAIL: mutexes (%d failures)\n", g_failures);
  return 1;
}
