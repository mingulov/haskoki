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

static void write_config(const char *body) {
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
  write_config(kLimit2Config);
  fl = load_module(sop);
  rv = init_with(fl, mode);
  CHECK(rv == CKR_OK, "limit2/%s initialize ok", mode);
  if (rv != CKR_OK) {
    drop_config();
    return 1;
  }
  memset(&ti, 0, sizeof(ti));
  rv = fl->C_GetTokenInfo(0, &ti);
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
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s1);
  CHECK(rv == CKR_OK, "limit2/%s open #1 ok", mode);
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s2);
  CHECK(rv == CKR_OK, "limit2/%s open #2 ok", mode);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 2 && ti.ulRwSessionCount == 2,
        "limit2/%s live counts (2,2)", mode);
  /* Third open refuses WITHOUT touching the out handle. */
  s3 = CANARY64;
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s3);
  CHECK(rv == CKR_SESSION_COUNT, "limit2/%s third open refused (0x%lx)", mode,
        (unsigned long)rv);
  CHECK(s3 == CANARY64, "limit2/%s refusal writes no handle", mode);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 2, "limit2/%s counts stay 2",
        mode);
  /* Close frees capacity: reopen succeeds. */
  rv = fl->C_CloseSession(s1);
  CHECK(rv == CKR_OK, "limit2/%s close #1 ok", mode);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 1 && ti.ulRwSessionCount == 1,
        "limit2/%s live counts (1,1) after close", mode);
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s1);
  CHECK(rv == CKR_OK, "limit2/%s reopen ok after close", mode);
  rv = fl->C_CloseSession(s1);
  CHECK(rv == CKR_OK, "limit2/%s close reopened ok", mode);
  rv = fl->C_CloseSession(s2);
  CHECK(rv == CKR_OK, "limit2/%s close #2 ok", mode);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && ti.ulSessionCount == 0 && ti.ulRwSessionCount == 0,
        "limit2/%s live counts (0,0) after close-all", mode);
  /* RO/RW mix: the RW count tracks RW sessions only. */
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &s1);
  CHECK(rv == CKR_OK, "limit2/%s open RO ok", mode);
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s2);
  CHECK(rv == CKR_OK, "limit2/%s open RW ok", mode);
  rv = fl->C_GetTokenInfo(0, &ti);
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

static int child_multitoken(const char *sop) {
  CK_FUNCTION_LIST_PTR fl;
  CK_TOKEN_INFO t0, t1;
  CK_SESSION_HANDLE a, b, c;
  CK_RV rv;
  write_config(kMultitoken2Config);
  fl = load_module(sop);
  rv = fl->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "multitoken initialize ok");
  if (rv != CKR_OK) {
    drop_config();
    return 1;
  }
  memset(&t0, 0, sizeof(t0));
  memset(&t1, 0, sizeof(t1));
  rv = fl->C_GetTokenInfo(0, &t0);
  CHECK(rv == CKR_OK, "multitoken slot0 tokeninfo ok");
  rv = fl->C_GetTokenInfo(1, &t1);
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
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &a);
  CHECK(rv == CKR_OK, "multitoken slot0 open #1 ok");
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &b);
  CHECK(rv == CKR_OK, "multitoken slot0 open #2 ok");
  c = CANARY64;
  rv = fl->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &c);
  CHECK(rv == CKR_SESSION_COUNT, "multitoken slot1 refused at cap (0x%lx)",
        (unsigned long)rv);
  CHECK(c == CANARY64, "multitoken cross-slot refusal writes no handle");
  rv = fl->C_GetTokenInfo(0, &t0);
  CHECK(rv == CKR_OK && t0.ulSessionCount == 2, "multitoken slot0 live 2");
  rv = fl->C_GetTokenInfo(1, &t1);
  CHECK(rv == CKR_OK && t1.ulSessionCount == 0, "multitoken slot1 live 0");
  /* Closing on slot 0 frees provider capacity for slot 1. */
  rv = fl->C_CloseSession(a);
  CHECK(rv == CKR_OK, "multitoken slot0 close ok");
  rv = fl->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &c);
  CHECK(rv == CKR_OK, "multitoken slot1 open ok after free");
  rv = fl->C_GetTokenInfo(0, &t0);
  CHECK(rv == CKR_OK && t0.ulSessionCount == 1, "multitoken slot0 live 1");
  rv = fl->C_GetTokenInfo(1, &t1);
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
    "labels = [\"haskoki-demo\"]\n"
    "so_pins = [\"5678\"]\n"
    "user_pins = [\"1234\"]\n";

static int child_pin(const char *sop) {
  CK_FUNCTION_LIST_PTR fl;
  CK_TOKEN_INFO ti;
  CK_SESSION_HANDLE s;
  CK_RV rv;
  write_config(kPinConfig);
  fl = load_module(sop);
  rv = fl->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "pin initialize ok");
  if (rv != CKR_OK) {
    drop_config();
    return 1;
  }
  memset(&ti, 0, sizeof(ti));
  rv = fl->C_GetTokenInfo(0, &ti);
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
  rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                         NULL_PTR, &s);
  CHECK(rv == CKR_OK, "pin open ok");
  /* Normal PIN authenticates, then logs out cleanly. */
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECK(rv == CKR_OK, "pin correct user login ok");
  rv = fl->C_Logout(s);
  CHECK(rv == CKR_OK, "pin logout ok");
  /* Retry progression: 3 attempts, COUNT_LOW at 2 left, FINAL_TRY
   * at 1 left, LOCKED after the third failure. */
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECK(rv == CKR_PIN_INCORRECT, "pin bad #1 incorrect (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && (ti.flags & CKF_USER_PIN_COUNT_LOW) != 0 &&
            (ti.flags & CKF_USER_PIN_FINAL_TRY) == 0,
        "pin count-low after 1 failure");
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECK(rv == CKR_PIN_INCORRECT, "pin bad #2 incorrect (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && (ti.flags & CKF_USER_PIN_FINAL_TRY) != 0,
        "pin final-try after 2 failures");
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECK(rv == CKR_PIN_LOCKED, "pin bad #3 locked (0x%lx)", (unsigned long)rv);
  rv = fl->C_GetTokenInfo(0, &ti);
  CHECK(rv == CKR_OK && (ti.flags & CKF_USER_PIN_LOCKED) != 0,
        "pin user-locked flag after lockout");
  /* A locked role stays locked even for the right PIN. */
  rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECK(rv == CKR_PIN_LOCKED, "pin locked denies correct pin (0x%lx)",
        (unsigned long)rv);
  /* Pre-provisioning: PIN setup stays an explicit stub refusal. */
  rv = fl->C_InitPIN(s, (CK_UTF8CHAR_PTR)"9999", 4);
  CHECK(rv == CKR_FUNCTION_NOT_SUPPORTED, "pin InitPIN pre-provisioning stub (0x%lx)",
        (unsigned long)rv);
  rv = fl->C_SetPIN(s, (CK_UTF8CHAR_PTR)"1234", 4, (CK_UTF8CHAR_PTR)"9999", 4);
  CHECK(rv == CKR_FUNCTION_NOT_SUPPORTED, "pin SetPIN pre-provisioning stub (0x%lx)",
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
static int child_pin_refuse(const char *sop, const char *user_pin,
                            const char *tag) {
  char body[2048];
  CK_FUNCTION_LIST_PTR fl;
  CK_RV rv;
  CK_ULONG n = 0;
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
  write_config(body);
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
