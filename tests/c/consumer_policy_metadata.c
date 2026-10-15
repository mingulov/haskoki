/* tests/c/consumer_policy_metadata.c — direct-load consumer: effective
 * session/PIN policy metadata.
 *
 * Standalone C consumer (non-Haskell executable): drives the native
 * metadata surface (C_GetTokenInfo) and session admission
 * (C_OpenSession) through the pinned 3.2 headers and asserts both
 * read the ONE effective policy:
 *   - provider-wide session capacity vs per-token maxima vs live
 *     counts are distinguished (a 2-session provider with 2 tokens
 *     refuses the third open wherever it lands, while each token
 *     reports max 2 with its own live counts)
 *   - non-default limit 2: third-open refusal (CKR_SESSION_COUNT),
 *     close/reopen capacity, no out-parameter writes on refusal
 *     (canaried handle/buffer stay intact)
 *   - coherent PIN bounds 4..32 from the same policy: one-byte and
 *     over-limit (33-byte) configured PINs refuse at C_Initialize
 *     (config invalid), a normal 4-byte PIN serves with the reported
 *     bounds, initialization flags, and retry/lock flag progression
 *   - OS-locking, application-mutex, and NULL init-arg modes agree
 *   - C_InitPIN/C_SetPIN stay FUNCTION_NOT_SUPPORTED until user
 *     provisioning lands (pinned pre-provisioning behavior, not new API)
 *
 * Supervisor shape (mirrors async_routed.c): with no scenario argv
 * the supervisor never loads the module and re-execs one child per
 * scenario over /proc/self/exe, so every scenario gets a hermetic
 * process, config file, and provider init. Each child dlopen()s the
 * built libhaskoki shared module given as argv[1].
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_policy_metadata <path-to-libhaskoki.so> [scenario]
 *        consumer_policy_metadata <so> --print-config <scenario>
 *
 * Topology: HASKOKI_CONSUMER_TOPOLOGY=proxy means the module is a
 * pkcs11 shim whose daemon already holds the scenario config, so the
 * child neither writes a config nor sets HASKOKI_CONFIG. In both
 * topologies the child verifies the backend identity (slot count,
 * token labels, session maximum) right after C_Initialize and exits 3
 * on a mismatch before any session is opened.
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("FAIL [%s:%d]: ", __FILE__, __LINE__);                        \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("ok: ");                                                      \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

#define CANARY64 ((CK_ULONG)0xA5A5A5A5A5A5A5A5UL)

/* ------------------------------------------------------------------ */
/* hermetic config                                                     */
/* ------------------------------------------------------------------ */

static char g_cfg_path[256];
static int g_cfg_ours = 0;

static int proxy_mode(void) {
  const char *t = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  return t != NULL && strcmp(t, "proxy") == 0;
}

static void write_config(const char *body) {
  if (proxy_mode()) {
    if (getenv("HASKOKI_CONFIG") != NULL) {
      unsetenv("HASKOKI_CONFIG");
    }
    printf("topology:policy-config=daemon\n");
    return;
  }
  char tmpl[] = "/tmp/haskoki-polmeta-XXXXXX";
  int fd = mkstemp(tmpl);
  size_t want;
  if (fd < 0) {
    perror("mkstemp");
    exit(2);
  }
  want = strlen(body);
  if (write(fd, body, want) != (ssize_t)want) {
    perror("write");
    exit(2);
  }
  close(fd);
  snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", tmpl);
  g_cfg_ours = 1;
  if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

static void drop_config(void) {
  if (g_cfg_ours) {
    unlink(g_cfg_path);
    g_cfg_ours = 0;
  }
}

/* ------------------------------------------------------------------ */
/* module load + init modes                                            */
/* ------------------------------------------------------------------ */

static CK_RV app_CreateMutex(CK_VOID_PTR_PTR ppMutex) {
  pthread_mutex_t *m = (pthread_mutex_t *)malloc(sizeof(*m));
  if (m == NULL_PTR) {
    return CKR_HOST_MEMORY;
  }
  if (pthread_mutex_init(m, NULL) != 0) {
    free(m);
    return CKR_GENERAL_ERROR;
  }
  *ppMutex = (CK_VOID_PTR)m;
  return CKR_OK;
}

static CK_RV app_DestroyMutex(CK_VOID_PTR pMutex) {
  pthread_mutex_t *m = (pthread_mutex_t *)pMutex;
  if (m == NULL_PTR) {
    return CKR_MUTEX_BAD;
  }
  pthread_mutex_destroy(m);
  free(m);
  return CKR_OK;
}

static CK_RV app_LockMutex(CK_VOID_PTR pMutex) {
  if (pMutex == NULL_PTR) {
    return CKR_MUTEX_BAD;
  }
  return pthread_mutex_lock((pthread_mutex_t *)pMutex) == 0 ? CKR_OK
                                                            : CKR_GENERAL_ERROR;
}

static CK_RV app_UnlockMutex(CK_VOID_PTR pMutex) {
  if (pMutex == NULL_PTR) {
    return CKR_MUTEX_BAD;
  }
  return pthread_mutex_unlock((pthread_mutex_t *)pMutex) == 0
             ? CKR_OK
             : CKR_GENERAL_ERROR;
}

/* Init locking mode: "null" (NULL args), "os" (CKF_OS_LOCKING_OK),
 * "app" (application mutex callbacks). */
static CK_RV init_with(CK_FUNCTION_LIST_PTR fl, const char *mode) {
  CK_C_INITIALIZE_ARGS args;
  if (strcmp(mode, "null") == 0) {
    return fl->C_Initialize(NULL_PTR);
  }
  memset(&args, 0, sizeof(args));
  if (strcmp(mode, "os") == 0) {
    args.flags = CKF_OS_LOCKING_OK;
    return fl->C_Initialize(&args);
  }
  args.CreateMutex = app_CreateMutex;
  args.DestroyMutex = app_DestroyMutex;
  args.LockMutex = app_LockMutex;
  args.UnlockMutex = app_UnlockMutex;
  return fl->C_Initialize(&args);
}

static CK_FUNCTION_LIST_PTR load_module(const char *sop) {
  void *handle = dlopen(sop, RTLD_NOW | RTLD_LOCAL);
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR fl = NULL_PTR;
  CK_RV rv;
  if (handle == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    exit(2);
  }
  pGetList =
      (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (pGetList == NULL) {
    fprintf(stderr, "C_GetFunctionList missing\n");
    exit(2);
  }
  rv = pGetList(&fl);
  if (rv != CKR_OK || fl == NULL_PTR) {
    fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
    exit(2);
  }
  return fl;
}

/* ------------------------------------------------------------------ */
/* backend identity: the scenario's expected backend shape            */
/* ------------------------------------------------------------------ */

typedef struct {
  const char *name;
  CK_ULONG slots;
  const char *labels[2];
  CK_ULONG max_sessions; /* ulMaxSessionCount of slot 0 */
} scenario_expect;

/* limit2-*: [limits] sessions = 2, one token. multitoken: sessions 2,
 * two tokens. pin: no [limits], two tokens (demo + haskoki-pin) with
 * their own PINs; ulMaxSessionCount is the module's default of 1024. */
static const scenario_expect kExpect[] = {
    {"limit2-null", 1, {"haskoki-demo", NULL}, 2},
    {"limit2-os", 1, {"haskoki-demo", NULL}, 2},
    {"limit2-app", 1, {"haskoki-demo", NULL}, 2},
    {"multitoken", 2, {"haskoki-demo", "haskoki-ops"}, 2},
    /* pin: a second token (slot 0 must stay haskoki-demo) and its own
     * PINs, so a daemon on any other config is refused by the identity
     * check (slot count) and by the login below (PIN) */
    {"pin", 2, {"haskoki-demo", "haskoki-pin"}, 1024},
};

/* Slot ids as published by the module under test: 0-based direct, but
 * the pinned proxy shim numbers them from 1, so every slot-addressed
 * call goes through g_slot[] (filled by check_backend from
 * C_GetSlotList, in list order). */
static CK_SLOT_ID g_slot[2];

static void backend_mismatch(const char *field, const char *want,
                             const char *got) {
  printf("policy:backend-mismatch %s want=%s got=%s\n", field, want, got);
  fflush(NULL);
  drop_config();
  exit(3);
}

static void trim_label(const CK_UTF8CHAR *raw, char *out) {
  size_t n = 32;
  memcpy(out, raw, n);
  while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\0')) {
    n--;
  }
  out[n] = '\0';
}

/* Right after C_Initialize, before any session: verify the backend is
 * the one this scenario expects (slot count, each token label, session
 * maximum). Exit 3 on mismatch; print the identity line on a match. */
static void check_backend(CK_FUNCTION_LIST_PTR fl, const char *name) {
  const scenario_expect *e = NULL;
  size_t i;
  CK_ULONG n = 0;
  CK_RV rv;
  char want[64], got[64], lab[40];
  CK_TOKEN_INFO ti;
  for (i = 0; i < sizeof(kExpect) / sizeof(kExpect[0]); i++) {
    if (strcmp(kExpect[i].name, name) == 0) {
      e = &kExpect[i];
    }
  }
  if (e == NULL) {
    fprintf(stderr, "no backend expectation for %s\n", name);
    exit(2);
  }
  rv = fl->C_GetSlotList(CK_TRUE, NULL_PTR, &n);
  if (rv != CKR_OK) {
    snprintf(want, sizeof(want), "%lu", (unsigned long)e->slots);
    snprintf(got, sizeof(got), "rv=0x%lx", (unsigned long)rv);
    backend_mismatch("slots", want, got);
  }
  if (n != e->slots) {
    snprintf(want, sizeof(want), "%lu", (unsigned long)e->slots);
    snprintf(got, sizeof(got), "%lu", (unsigned long)n);
    backend_mismatch("slots", want, got);
  }
  {
    CK_SLOT_ID ids[8];
    CK_ULONG got_n = sizeof(ids) / sizeof(ids[0]);
    rv = fl->C_GetSlotList(CK_TRUE, ids, &got_n);
    if (rv != CKR_OK || got_n != e->slots || e->slots > 2) {
      snprintf(want, sizeof(want), "%lu", (unsigned long)e->slots);
      snprintf(got, sizeof(got), "list rv=0x%lx n=%lu", (unsigned long)rv,
               (unsigned long)got_n);
      backend_mismatch("slot-list", want, got);
    }
    for (i = 0; i < e->slots; i++) {
      g_slot[i] = ids[i];
    }
  }
  for (i = 0; i < e->slots; i++) {
    char field[16];
    snprintf(field, sizeof(field), "label[%zu]", i);
    memset(&ti, 0, sizeof(ti));
    rv = fl->C_GetTokenInfo(g_slot[i], &ti);
    if (rv != CKR_OK) {
      snprintf(got, sizeof(got), "rv=0x%lx", (unsigned long)rv);
      backend_mismatch(field, e->labels[i], got);
    }
    trim_label(ti.label, lab);
    if (strcmp(lab, e->labels[i]) != 0) {
      backend_mismatch(field, e->labels[i], lab);
    }
    if (i == 0 && ti.ulMaxSessionCount != e->max_sessions) {
      snprintf(want, sizeof(want), "%lu", (unsigned long)e->max_sessions);
      snprintf(got, sizeof(got), "%lu", (unsigned long)ti.ulMaxSessionCount);
      backend_mismatch("max", want, got);
    }
  }
  printf("policy:backend slots=%lu max=%lu\n", (unsigned long)e->slots,
         (unsigned long)e->max_sessions);
}

/* ------------------------------------------------------------------ */
/* limit-2 leg (single token): maxima, refusal, close/reopen, canary  */
/* ------------------------------------------------------------------ */

static const char kLimit2Config[] =
    "schema_version = 1\n"
    "profile = \"real-crypto\"\n"
    "[storage]\n"
    "kind = \"memory\"\n"
    "[engine]\n"
    "kind = \"openssl\"\n"
    "allow_synthetic_fallback = false\n"
    "private_library_context = true\n"
    "[trace]\n"
    "enabled = false\n"
    "[limits]\n"
    "sessions = 2\n"
    "[tokens]\n"
    "labels = [\"haskoki-demo\"]\n"
    "so_pins = [\"5678\"]\n"
    "user_pins = [\"1234\"]\n";

static const char *toml_limit2(void) { return kLimit2Config; }

static int all_canary(const unsigned char *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (p[i] != 0xA5) {
      return 0;
    }
  }
  return 1;
}

/* Returns process exit status for the limit-2 child under one init
 * locking mode. */
static int child_limit2(const char *sop, const char *mode) {
  CK_FUNCTION_LIST_PTR fl;
  CK_TOKEN_INFO ti;
  CK_SESSION_HANDLE s1, s2, s3;
  CK_RV rv;
  write_config(toml_limit2());
  fl = load_module(sop);
  rv = init_with(fl, mode);
  if (proxy_mode() && strcmp(mode, "app") == 0) {
    /* Supported refusal of the pinned proxy shim: it cannot carry
     * application mutex callbacks across the process boundary, so it
     * refuses CKR_CANT_LOCK (observed on the pinned pair). Asserted
     * strictly: any other result fails. The topology: line is excluded
     * from the direct/proxied diff; the session legs then run on an OS
     * locking init so the policy assertions stay compared. */
    printf("topology:limit2/app application-mutex init refused (0x%lx)\n",
           (unsigned long)rv);
    if (rv != CKR_CANT_LOCK) {
      printf("FAIL [%s:%d]: limit2/app proxied init want CKR_CANT_LOCK "
             "got 0x%lx\n",
             __FILE__, __LINE__, (unsigned long)rv);
      drop_config();
      return 1;
    }
    rv = init_with(fl, "os");
  }
  CHECK(rv == CKR_OK, "limit2/%s initialize ok (0x%lx)", mode,
        (unsigned long)rv);
  if (rv != CKR_OK) {
    drop_config();
    return 1;
  }
  {
    char nm[32];
    snprintf(nm, sizeof(nm), "limit2-%s", mode);
    check_backend(fl, nm);
  }
  memset(&ti, 0, sizeof(ti));
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK, "limit2/%s tokeninfo ok", mode);
  CHECK(ti.ulMaxSessionCount == 2, "limit2/%s max sessions 2 (got %lu)",
        mode, (unsigned long)ti.ulMaxSessionCount);
  CHECK(ti.ulMaxRwSessionCount == 2, "limit2/%s max rw 2 (got %lu)", mode,
        (unsigned long)ti.ulMaxRwSessionCount);
  CHECK(ti.ulSessionCount == 0, "limit2/%s live count 0", mode);
  CHECK(ti.ulRwSessionCount == 0, "limit2/%s live rw 0", mode);
  CHECK(ti.ulMinPinLen == 4, "limit2/%s pin min 4 (got %lu)", mode,
        (unsigned long)ti.ulMinPinLen);
  CHECK(ti.ulMaxPinLen == 32, "limit2/%s pin max 32 (got %lu)", mode,
        (unsigned long)ti.ulMaxPinLen);
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s1);
  CHECK(rv == CKR_OK, "limit2/%s open #1 ok", mode);
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s2);
  CHECK(rv == CKR_OK, "limit2/%s open #2 ok", mode);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 2 && ti.ulRwSessionCount == 2,
        "limit2/%s live counts (2,2)", mode);
  /* Third open refuses WITHOUT touching the out handle. */
  s3 = CANARY64;
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s3);
  CHECK(rv == CKR_SESSION_COUNT, "limit2/%s third open refused (0x%lx)", mode,
        (unsigned long)rv);
  CHECK(s3 == CANARY64, "limit2/%s refusal writes no handle", mode);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 2, "limit2/%s counts stay 2",
        mode);
  /* Close frees capacity: reopen succeeds. */
  rv = fl->C_CloseSession(s1);
  CHECK(rv == CKR_OK, "limit2/%s close #1 ok", mode);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 1 && ti.ulRwSessionCount == 1,
        "limit2/%s live counts (1,1) after close", mode);
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s1);
  CHECK(rv == CKR_OK, "limit2/%s reopen ok after close", mode);
  rv = fl->C_CloseSession(s1);
  CHECK(rv == CKR_OK, "limit2/%s close reopened ok", mode);
  rv = fl->C_CloseSession(s2);
  CHECK(rv == CKR_OK, "limit2/%s close #2 ok", mode);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 0 && ti.ulRwSessionCount == 0,
        "limit2/%s live counts (0,0) after close-all", mode);
  /* RO/RW mix: the RW count tracks RW sessions only. */
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &s1);
  CHECK(rv == CKR_OK, "limit2/%s open RO ok", mode);
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s2);
  CHECK(rv == CKR_OK, "limit2/%s open RW ok", mode);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 2 && ti.ulRwSessionCount == 1,
        "limit2/%s live counts (2,1) for RO+RW", mode);
  rv = fl->C_CloseSession(s1);
  CHECK(rv == CKR_OK, "limit2/%s close RO ok", mode);
  rv = fl->C_CloseSession(s2);
  CHECK(rv == CKR_OK, "limit2/%s close RW ok", mode);
  /* Bad-slot metadata refusal writes nothing. */
  memset(&ti, 0xA5, sizeof(ti));
  rv = fl->C_GetTokenInfo(99, &ti);
  CHECK(rv == CKR_SLOT_ID_INVALID, "limit2/%s bad slot refused (0x%lx)", mode,
        (unsigned long)rv);
  CHECK(all_canary((const unsigned char *)&ti, sizeof(ti)),
        "limit2/%s bad-slot refusal writes nothing", mode);
  rv = fl->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "limit2/%s finalize ok", mode);
  drop_config();
  if (g_failures == 0) {
    printf("PASS: consumer_policy_metadata/limit2-%s\n", mode);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}

/* ------------------------------------------------------------------ */
/* multitoken leg: provider capacity vs per-token maxima               */
/* ------------------------------------------------------------------ */

static const char kMultitoken2Config[] =
    "schema_version = 1\n"
    "profile = \"real-crypto\"\n"
    "[storage]\n"
    "kind = \"memory\"\n"
    "[engine]\n"
    "kind = \"openssl\"\n"
    "allow_synthetic_fallback = false\n"
    "private_library_context = true\n"
    "[trace]\n"
    "enabled = false\n"
    "[limits]\n"
    "sessions = 2\n"
    "[tokens]\n"
    "labels = [\"haskoki-demo\", \"haskoki-ops\"]\n"
    "so_pins = [\"5678\", \"6789\"]\n"
    "user_pins = [\"1234\", \"2345\"]\n";

static const char *toml_multitoken(void) { return kMultitoken2Config; }

static int child_multitoken(const char *sop) {
  CK_FUNCTION_LIST_PTR fl;
  CK_TOKEN_INFO t0, t1;
  CK_SESSION_HANDLE a, b, c;
  CK_RV rv;
  write_config(toml_multitoken());
  fl = load_module(sop);
  rv = fl->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "multitoken initialize ok");
  if (rv != CKR_OK) {
    drop_config();
    return 1;
  }
  check_backend(fl, "multitoken");
  memset(&t0, 0, sizeof(t0));
  memset(&t1, 0, sizeof(t1));
  rv = fl->C_GetTokenInfo(g_slot[0], &t0);
  CHECK(rv == CKR_OK, "multitoken slot0 tokeninfo ok");
  rv = fl->C_GetTokenInfo(g_slot[1], &t1);
  CHECK(rv == CKR_OK, "multitoken slot1 tokeninfo ok");
  /* Each token reports the per-token maxima (2 = full provider
   * capacity: one token may use it all) with its own live counts. */
  CHECK(t0.ulMaxSessionCount == 2 && t1.ulMaxSessionCount == 2,
        "multitoken per-token max 2 on both slots");
  CHECK(t0.ulMaxRwSessionCount == 2 && t1.ulMaxRwSessionCount == 2,
        "multitoken per-token rw max 2 on both slots");
  CHECK(t0.ulMinPinLen == 4 && t0.ulMaxPinLen == 32,
        "multitoken slot0 pin bounds 4..32");
  CHECK(t1.ulMinPinLen == 4 && t1.ulMaxPinLen == 32,
        "multitoken slot1 pin bounds 4..32");
  /* Two opens on slot 0 consume the PROVIDER capacity: slot 1's
   * open refuses even though slot 1 shows live count 0. */
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &a);
  CHECK(rv == CKR_OK, "multitoken slot0 open #1 ok");
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &b);
  CHECK(rv == CKR_OK, "multitoken slot0 open #2 ok");
  c = CANARY64;
  rv = fl->C_OpenSession(g_slot[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &c);
  CHECK(rv == CKR_SESSION_COUNT, "multitoken slot1 refused at cap (0x%lx)",
        (unsigned long)rv);
  CHECK(c == CANARY64, "multitoken cross-slot refusal writes no handle");
  rv = fl->C_GetTokenInfo(g_slot[0], &t0);
  CHECK(rv == CKR_OK && t0.ulSessionCount == 2, "multitoken slot0 live 2");
  rv = fl->C_GetTokenInfo(g_slot[1], &t1);
  CHECK(rv == CKR_OK && t1.ulSessionCount == 0, "multitoken slot1 live 0");
  /* Closing on slot 0 frees provider capacity for slot 1. */
  rv = fl->C_CloseSession(a);
  CHECK(rv == CKR_OK, "multitoken slot0 close ok");
  rv = fl->C_OpenSession(g_slot[1], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &c);
  CHECK(rv == CKR_OK, "multitoken slot1 open ok after free");
  rv = fl->C_GetTokenInfo(g_slot[0], &t0);
  CHECK(rv == CKR_OK && t0.ulSessionCount == 1, "multitoken slot0 live 1");
  rv = fl->C_GetTokenInfo(g_slot[1], &t1);
  CHECK(rv == CKR_OK && t1.ulSessionCount == 1 && t1.ulRwSessionCount == 1,
        "multitoken slot1 live (1,1)");
  rv = fl->C_CloseSession(b);
  CHECK(rv == CKR_OK, "multitoken slot0 close #2 ok");
  rv = fl->C_CloseSession(c);
  CHECK(rv == CKR_OK, "multitoken slot1 close ok");
  rv = fl->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "multitoken finalize ok");
  drop_config();
  if (g_failures == 0) {
    printf("PASS: consumer_policy_metadata/multitoken\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}

/* ------------------------------------------------------------------ */
/* PIN legs: bounds, flags, retry/lock progression, setup stubs       */
/* ------------------------------------------------------------------ */

static const char kPinConfig[] =
    "schema_version = 1\n"
    "profile = \"real-crypto\"\n"
    "[storage]\n"
    "kind = \"memory\"\n"
    "[engine]\n"
    "kind = \"openssl\"\n"
    "allow_synthetic_fallback = false\n"
    "private_library_context = true\n"
    "[trace]\n"
    "enabled = false\n"
    "[tokens]\n"
    "labels = [\"haskoki-demo\", \"haskoki-pin\"]\n"
    "so_pins = [\"8765\", \"7654\"]\n"
    "user_pins = [\"4321\", \"3210\"]\n";

static const char *toml_pin(void) { return kPinConfig; }

static int child_pin(const char *sop) {
  CK_FUNCTION_LIST_PTR fl;
  CK_TOKEN_INFO ti;
  CK_SESSION_HANDLE s;
  CK_RV rv;
  write_config(toml_pin());
  fl = load_module(sop);
  rv = fl->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "pin initialize ok");
  if (rv != CKR_OK) {
    drop_config();
    return 1;
  }
  check_backend(fl, "pin");
  memset(&ti, 0, sizeof(ti));
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK, "pin tokeninfo ok");
  CHECK(ti.ulMinPinLen == 4 && ti.ulMaxPinLen == 32,
        "pin reported bounds 4..32 (got %lu..%lu)",
        (unsigned long)ti.ulMinPinLen, (unsigned long)ti.ulMaxPinLen);
  CHECK((ti.flags & CKF_TOKEN_INITIALIZED) != 0, "pin token-initialized set");
  CHECK((ti.flags & CKF_LOGIN_REQUIRED) != 0, "pin login-required set");
  CHECK((ti.flags & CKF_USER_PIN_INITIALIZED) != 0, "pin user-init set");
  CHECK((ti.flags & CKF_USER_PIN_LOCKED) == 0, "pin user-locked clear");
  CHECK((ti.flags & CKF_USER_PIN_COUNT_LOW) == 0, "pin count-low clear");
  CHECK((ti.flags & CKF_USER_PIN_FINAL_TRY) == 0, "pin final-try clear");
  rv = fl->C_OpenSession(g_slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s);
  CHECK(rv == CKR_OK, "pin open ok");
  /* Normal PIN authenticates, then logs out cleanly. */
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"4321", 4);
  CHECK(rv == CKR_OK, "pin correct user login ok");
  rv = fl->C_Logout(s);
  CHECK(rv == CKR_OK, "pin logout ok");
  /* Retry progression: 3 attempts, COUNT_LOW at 2 left, FINAL_TRY
   * at 1 left, LOCKED after the third failure. */
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECK(rv == CKR_PIN_INCORRECT, "pin bad #1 incorrect (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && (ti.flags & CKF_USER_PIN_COUNT_LOW) != 0 &&
            (ti.flags & CKF_USER_PIN_FINAL_TRY) == 0,
        "pin count-low after 1 failure");
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECK(rv == CKR_PIN_INCORRECT, "pin bad #2 incorrect (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && (ti.flags & CKF_USER_PIN_FINAL_TRY) != 0,
        "pin final-try after 2 failures");
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECK(rv == CKR_PIN_LOCKED, "pin bad #3 locked (0x%lx)", (unsigned long)rv);
  rv = fl->C_GetTokenInfo(g_slot[0], &ti);
  CHECK(rv == CKR_OK && (ti.flags & CKF_USER_PIN_LOCKED) != 0,
        "pin user-locked flag after lockout");
  /* A locked role stays locked even for the right PIN. */
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"4321", 4);
  CHECK(rv == CKR_PIN_LOCKED, "pin locked denies correct pin (0x%lx)",
        (unsigned long)rv);
  /* Provisioned: PIN setup is live. InitPIN needs an SO session,
     and SetPIN on the locked role stays locked. */
  rv = fl->C_InitPIN(s, (CK_UTF8CHAR_PTR)"9999", 4);
  CHECK(rv == CKR_USER_NOT_LOGGED_IN, "pin InitPIN needs SO (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_SetPIN(s, (CK_UTF8CHAR_PTR)"4321", 4, (CK_UTF8CHAR_PTR)"9999", 4);
  CHECK(rv == CKR_PIN_LOCKED, "pin SetPIN locked role stays locked (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_CloseSession(s);
  CHECK(rv == CKR_OK, "pin close ok");
  rv = fl->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "pin finalize ok");
  drop_config();
  if (g_failures == 0) {
    printf("PASS: consumer_policy_metadata/pin\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}

/* Out-of-policy configured PINs refuse at init: the config never
 * loads, so init fails loudly and nothing is half-installed. */
/* TOML for the bad-PIN scenarios (user PIN out of the 4..32 policy). */
static const char *toml_pin_refuse(const char *user_pin) {
  static char body[2048];
  int w = snprintf(body, sizeof(body),
                   "schema_version = 1\n"
                   "profile = \"real-crypto\"\n"
                   "[storage]\n"
                   "kind = \"memory\"\n"
                   "[engine]\n"
                   "kind = \"openssl\"\n"
                   "allow_synthetic_fallback = false\n"
                   "private_library_context = true\n"
                   "[trace]\n"
                   "enabled = false\n"
                   "[tokens]\n"
                   "labels = [\"haskoki-demo\"]\n"
                   "so_pins = [\"5678\"]\n"
                   "user_pins = [\"%s\"]\n",
                   user_pin);
  if (w < 0 || (size_t)w >= sizeof(body)) {
    fprintf(stderr, "config body too long\n");
    exit(2);
  }
  return body;
}

static int child_pin_refuse(const char *sop, const char *user_pin,
                            const char *tag) {
  CK_FUNCTION_LIST_PTR fl;
  CK_RV rv;
  CK_ULONG n = 0;
  if (proxy_mode()) {
    /* The bad config would fail at the daemon's backend load, not at a
     * C_Initialize the consumer can observe. */
    printf("policy:pin-refuse proxy-mode unsupported\n");
    return 4;
  }
  write_config(toml_pin_refuse(user_pin));
  fl = load_module(sop);
  rv = fl->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_GENERAL_ERROR, "pin-%s init refused (0x%lx)", tag,
        (unsigned long)rv);
  rv = fl->C_GetSlotList(0, NULL_PTR, &n);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "pin-%s nothing half-installed (0x%lx)", tag, (unsigned long)rv);
  drop_config();
  if (g_failures == 0) {
    printf("PASS: consumer_policy_metadata/pin-%s\n", tag);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}

/* ------------------------------------------------------------------ */
/* supervisor: one hermetic child per scenario                         */
/* ------------------------------------------------------------------ */

static int run_child(const char *self, const char *sop, const char *scen) {
  pid_t pid;
  int status;
  if (fflush(NULL) != 0) {
    perror("fflush");
    return 0;
  }
  pid = fork();
  if (pid < 0) {
    perror("fork");
    return 0;
  }
  if (pid == 0) {
    execl("/proc/self/exe", self, sop, scen, (char *)NULL);
    perror("execl");
    _Exit(2);
  }
  for (;;) {
    pid_t w = waitpid(pid, &status, 0);
    if (w == pid) {
      break;
    }
    if (w < 0 && errno != EINTR) {
      perror("waitpid");
      return 0;
    }
  }
  if (WIFEXITED(status)) {
    printf("policy:child/%s exit=%d\n", scen, WEXITSTATUS(status));
    return WEXITSTATUS(status) == 0;
  }
  printf("policy:child/%s signal=%d\n", scen,
         WIFSIGNALED(status) ? WTERMSIG(status) : -1);
  return 0;
}

int main(int argc, char **argv) {
  static const char *kScenarios[] = {
      "limit2-null", "limit2-os", "limit2-app", "multitoken", "pin",
      "pin-short", "pin-empty", "pin-long",
  };
  size_t i;
  int ok = 1;
  if (argc < 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so> [scenario]\n", argv[0]);
    return 2;
  }
  if (argc >= 3 && strcmp(argv[2], "--print-config") == 0) {
    const char *scen = argc >= 4 ? argv[3] : "";
    const char *toml = NULL;
    if (strncmp(scen, "limit2-", 7) == 0 &&
        (strcmp(scen + 7, "null") == 0 || strcmp(scen + 7, "os") == 0 ||
         strcmp(scen + 7, "app") == 0)) {
      toml = toml_limit2();
    } else if (strcmp(scen, "multitoken") == 0) {
      toml = toml_multitoken();
    } else if (strcmp(scen, "pin") == 0) {
      toml = toml_pin();
    } else if (strcmp(scen, "pin-short") == 0) {
      toml = toml_pin_refuse("X");
    } else if (strcmp(scen, "pin-empty") == 0) {
      toml = toml_pin_refuse("");
    } else if (strcmp(scen, "pin-long") == 0) {
      toml = toml_pin_refuse("123456789012345678901234567890123");
    }
    if (toml == NULL) {
      fprintf(stderr, "unknown scenario: %s\n", scen);
      return 2;
    }
    fputs(toml, stdout);
    return 0;
  }
  if (argc >= 3) {
    const char *scen = argv[2];
    if (strcmp(scen, "limit2-null") == 0) {
      return child_limit2(argv[1], "null");
    }
    if (strcmp(scen, "limit2-os") == 0) {
      return child_limit2(argv[1], "os");
    }
    if (strcmp(scen, "limit2-app") == 0) {
      return child_limit2(argv[1], "app");
    }
    if (strcmp(scen, "multitoken") == 0) {
      return child_multitoken(argv[1]);
    }
    if (strcmp(scen, "pin") == 0) {
      return child_pin(argv[1]);
    }
    if (strcmp(scen, "pin-short") == 0) {
      return child_pin_refuse(argv[1], "X", "short");
    }
    if (strcmp(scen, "pin-empty") == 0) {
      return child_pin_refuse(argv[1], "", "empty");
    }
    if (strcmp(scen, "pin-long") == 0) {
      return child_pin_refuse(argv[1], "123456789012345678901234567890123",
                              "long");
    }
    fprintf(stderr, "unknown scenario: %s\n", scen);
    return 2;
  }
  /* Supervisor: never loads the module (fork never copies a live
   * RTS); one hermetic child per scenario. */
  for (i = 0; i < sizeof(kScenarios) / sizeof(kScenarios[0]); i++) {
    if (!run_child(argv[0], argv[1], kScenarios[i])) {
      ok = 0;
    }
  }
  if (ok) {
    printf("PASS: consumer_policy_metadata (%s)\n", argv[1]);
    return 0;
  }
  printf("FAIL: consumer_policy_metadata (%s)\n", argv[1]);
  return 1;
}
