/* tests/c/consumer_errors.c — error-code proof: ReturnCodes on
 * error probes are UNCHANGED by the error unification, across the
 * legacy 2.40 + 3.x tables:
 *   - bogus mechanism init is CKR_MECHANISM_INVALID
 *   - NULL mechanism init is CKR_ARGUMENTS_BAD
 *   - template-count overflow on C_GetAttributeValue is
 *     CKR_ARGUMENTS_BAD (64-entry bound shared with the pack path);
 *     a real 64-entry template over a live key still processes;
 *     the over-long-count-over-1-entry probe is direct-only (the
 *     shim reads the full count out of bounds in external code,
 *     so its outcome is garbage-determined), with a real-65-entry
 *     variant pinning the daemon-side bound in both topologies
 *   - final/update with no active op is CKR_OPERATION_NOT_INITIALIZED
 *   - short-buffer final/one-shot legs report CKR_BUFFER_TOO_SMALL
 *     with the required length
 *   - wrong PIN is CKR_PIN_INCORRECT; logout without login is
 *     CKR_USER_NOT_LOGGED_IN (login probes run once: token auth
 *     state is shared across tables in one process)
 *   - C_GetOperationState stays the honest unwired stub
 *     (CKR_FUNCTION_NOT_SUPPORTED); the unsaveable-stream save code
 *     (CKR_STATE_UNSAVEABLE) is pinned at the Haskell level by the
 *     existing SnapshotSpec/DetachedSpec suites (no C entry
 *     surfaces it either).
 *   - stub-beats-args precedence (NULL/garbage args to
 *     stubs yield the stub code on every table, incl. 3.0-only
 *     C_LoginUser) — direct-only: the proxy shim interposes its
 *     own forwarding behavior, so these pins assert our module's
 *     contract and stay out of the parity transcript (crypto: /
 *     invent: scoped, isProxy-gated).
 *   - C_OpenSession accepts a non-NULL Notify (no
 *     callback-refusal code exists in the spec return list);
 *     the session is usable and the callback never fires
 *     (the module generates no notification events) —
 *     direct-only (a function pointer cannot cross the
 *     proxy).
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2
 * headers. Per-table scenario lines carry "crypto:" and the
 * 3.1-discovery line "invent:" (mirrors consumer_streaming.c: the
 * shim has no 3.1 table); setup/login lines are topology-independent
 * ("ok:"), so the parity script still diffs the shared transcript
 * direct-vs-proxied.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_errors <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Topology-scoped checks (mirrors consumer_streaming.c): per-table
 * scenario lines carry "crypto:" and 3.1-discovery lines "invent:",
 * so the parity script excludes exactly the lines that legitimately
 * diverge behind the shim (no 3.1 table there). */
#define CHECKC(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("crypto: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("crypto: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

#define CHECKM(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("invent: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("invent: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

static char g_cfg_path[256];

/* Session-notification probe: the module accepts a non-NULL
 * Notify (no callback-refusal code exists in the C_OpenSession
 * return list) but generates no notification events, so this
 * must never fire. */
static int g_notify_calls = 0;

static CK_RV err_notify_cb(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event,
                           CK_VOID_PTR pApplication) {
  (void)hSession;
  (void)event;
  (void)pApplication;
  g_notify_calls++;
  return CKR_OK;
}

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
  char tmpl[] = "/tmp/haskoki-errors-XXXXXX";
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

/* Per-table error probes. The table expression has that table's own
 * type, so each table's real entry points are exercised. */
#define ERRORS_SCENARIO(tag, T)                                            \
  do {                                                                     \
    CK_SESSION_HANDLE sess = 0;                                            \
    CK_MECHANISM mech;                                                     \
    CK_MECHANISM bogus;                                                    \
    CK_BYTE out[64];                                                       \
    CK_ULONG outLen;                                                       \
    CK_ULONG stateLen = 0;                                                 \
    CK_RV prv;                                                             \
    mech.mechanism = CKM_SHA256;                                           \
    mech.pParameter = NULL_PTR;                                            \
    mech.ulParameterLen = 0;                                               \
    bogus.mechanism = 0xDEADUL;                                            \
    bogus.pParameter = NULL_PTR;                                           \
    bogus.ulParameterLen = 0;                                              \
    prv = open_session_on((T), &sess);                                     \
    CHECKC(prv == CKR_OK && sess != 0, "%s: session opens", tag);            \
    /* Notify acceptance (direct-only: a function pointer cannot */         \
    /* cross the proxy). A supplied callback opens OK and the */            \
    /* session is usable; this open/info/close sequence emits */           \
    /* no callback. It does not exercise a Digest producer. */                                \
    if (!isProxy) {                                                        \
      CK_SESSION_HANDLE nsess = 0;                                         \
      CK_SESSION_INFO ninfo;                                               \
      g_notify_calls = 0;                                                  \
      prv = (T)->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,     \
                               &g_notify_calls, err_notify_cb, &nsess);    \
      if (prv == CKR_SLOT_ID_INVALID) {                                    \
        CK_SLOT_ID nsl[8];                                                 \
        CK_ULONG npn = 8;                                                  \
        if ((T)->C_GetSlotList(0, nsl, &npn) == CKR_OK && npn >= 1) {       \
          prv = (T)->C_OpenSession(nsl[0],                                \
                                   CKF_SERIAL_SESSION | CKF_RW_SESSION,    \
                                   &g_notify_calls, err_notify_cb, &nsess); \
        }                                                                  \
      }                                                                    \
      CHECKC(prv == CKR_OK && nsess != 0,                                  \
             "%s: notify session opens", tag);                                \
      if (prv == CKR_OK && nsess != 0) {                                   \
        prv = (T)->C_GetSessionInfo(nsess, &ninfo);                        \
        CHECKC(prv == CKR_OK, "%s: notify session info", tag);               \
        prv = (T)->C_CloseSession(nsess);                                  \
        CHECKC(prv == CKR_OK, "%s: notify session closes", tag);             \
      }                                                                    \
      CHECKC(g_notify_calls == 0, "%s: notify never fires", tag);            \
    }                                                                      \
    /* bad mechanism */                                                    \
    prv = (T)->C_DigestInit(sess, &bogus);                                 \
    CHECKC(prv == CKR_MECHANISM_INVALID, "%s: bogus init refused", tag);     \
    /* NULL mechanism */                                                   \
    prv = (T)->C_DigestInit(sess, NULL_PTR);                               \
    CHECKC(prv == CKR_ARGUMENTS_BAD, "%s: NULL init refused", tag);          \
    /* template-count overflow: huge ulCount over a 1-entry */             \
    /* template refuses loudly, never reads OOB (oracle probes */          \
    /* segfaulted pre-bound). */                                           \
    {                                                                      \
      CK_ATTRIBUTE one[1];                                                 \
      CK_BYTE val[8];                                                      \
      one[0].type = CKA_CLASS;                                             \
      one[0].pValue = val;                                                 \
      one[0].ulValueLen = sizeof(val);                                     \
      prv = (T)->C_GetAttributeValue(sess, 1, one, 0x100000000UL);          \
      CHECKC(prv == CKR_ARGUMENTS_BAD,                                     \
             "%s: getattr count overflow refused", tag);                   \
    }                                                                      \
    /* boundary variant: 65 entries (one past the 64-entry pack */          \
    /* bound) over a 1-entry template refuses the same way. */             \
    /* Direct-only: the count is checked before any entry is read, */      \
    /* so the over-long count never dereferences out of bounds. */         \
    /* Behind the proxy the SHIM reads all 65 entries out of bounds */     \
    /* in external code (shim object.rs has no 64-entry bound; its */      \
    /* MAX_TEMPLATE_COUNT is 65536), and the garbage entries decide */     \
    /* the outcome (HOST_MEMORY when a garbage length fails */             \
    /* try_reserve_exact in backend from_queries, ARGUMENTS_BAD */         \
    /* otherwise) -- stack-layout-determined, not our contract. */         \
    if (!isProxy) {                                                        \
      CK_ATTRIBUTE one[1];                                                 \
      CK_BYTE val[8];                                                      \
      one[0].type = CKA_CLASS;                                             \
      one[0].pValue = val;                                                 \
      one[0].ulValueLen = sizeof(val);                                     \
      prv = (T)->C_GetAttributeValue(sess, 1, one, 65);                     \
      CHECKC(prv == CKR_ARGUMENTS_BAD,                                     \
             "%s: getattr count 65 refused", tag);                         \
    }                                                                      \
    /* In-bounds variant, both topologies: a real 65-entry template */     \
    /* (benign size queries) still refuses at the bound -- direct at */    \
    /* our module, proxied at the daemon side after forwarding. */         \
    {                                                                      \
      CK_ATTRIBUTE many[65];                                               \
      int manyi;                                                           \
      for (manyi = 0; manyi < 65; manyi++) {                               \
        many[manyi].type = CKA_CLASS;                                      \
        many[manyi].pValue = NULL_PTR;                                     \
        many[manyi].ulValueLen = 0;                                        \
      }                                                                    \
      prv = (T)->C_GetAttributeValue(sess, 1, many, 65);                   \
      CHECKC(prv == CKR_ARGUMENTS_BAD,                                     \
             "%s: getattr real 65 refused", tag);                          \
    }                                                                      \
    /* boundary control: a real 64-entry template over a live key          \
     * processes (the bound refuses 65+, never 64). */                     \
    {                                                                      \
      CK_OBJECT_CLASS bkcls = CKO_SECRET_KEY;                              \
      CK_KEY_TYPE bkkt = CKK_AES;                                          \
      CK_ULONG bkvlen = 16;                                                \
      CK_BBOOL bkfalse = CK_FALSE;                                         \
      CK_OBJECT_HANDLE bkobj = 0;                                          \
      CK_ATTRIBUTE bktmpl[] = {                                            \
        { CKA_CLASS, &bkcls, sizeof(bkcls) },                              \
        { CKA_KEY_TYPE, &bkkt, sizeof(bkkt) },                             \
        { CKA_VALUE_LEN, &bkvlen, sizeof(bkvlen) },                        \
        { CKA_TOKEN, &bkfalse, sizeof(bkfalse) },                          \
      };                                                                   \
      CK_MECHANISM bkgm;                                                   \
      CK_ATTRIBUTE bq[64];                                                 \
      CK_BYTE bqv[64][16];                                                 \
      int bqi;                                                             \
      bkgm.mechanism = CKM_AES_KEY_GEN;                                    \
      bkgm.pParameter = NULL_PTR;                                          \
      bkgm.ulParameterLen = 0;                                             \
      prv = (T)->C_GenerateKey(sess, &bkgm, bktmpl, 4, &bkobj);            \
      CHECKC(prv == CKR_OK && bkobj != 0,                                  \
             "%s: bound-probe key mints", tag);                            \
      for (bqi = 0; bqi < 64; bqi++) {                                     \
        bq[bqi].type = CKA_CLASS;                                          \
        bq[bqi].pValue = bqv[bqi];                                         \
        bq[bqi].ulValueLen = sizeof(bqv[bqi]);                             \
      }                                                                    \
      prv = (T)->C_GetAttributeValue(sess, bkobj, bq, 64);                 \
      CHECKC(prv == CKR_OK,                                                \
             "%s: getattr count 64 processes", tag);                       \
    }                                                                      \
    /* final/update with no active op */                                   \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_OPERATION_NOT_INITIALIZED,                            \
          "%s: final without init refused", tag);                          \
    prv = (T)->C_DigestUpdate(sess, (CK_BYTE_PTR) "abc", 3);                \
    CHECKC(prv == CKR_OPERATION_NOT_INITIALIZED,                            \
          "%s: update without init refused", tag);                         \
    /* short-buffer final leg reports the length */                        \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: init for short final", tag);                 \
    prv = (T)->C_DigestUpdate(sess, (CK_BYTE_PTR) "abc", 3);                \
    CHECKC(prv == CKR_OK, "%s: update for short final", tag);               \
    outLen = 8;                                                            \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_BUFFER_TOO_SMALL && outLen == 32,                     \
          "%s: short final reports 32", tag);                              \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_OK && outLen == 32, "%s: exact retry completes",       \
          tag);                                                            \
    /* short-buffer one-shot leg */                                        \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: init for short one-shot", tag);              \
    outLen = 8;                                                            \
    prv = (T)->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, out, &outLen);        \
    CHECKC(prv == CKR_BUFFER_TOO_SMALL && outLen == 32,                     \
          "%s: short one-shot reports 32", tag);                           \
    /* unsaveable stub stays honest */                                     \
    prv = (T)->C_GetOperationState(sess, NULL_PTR, &stateLen);             \
    CHECKC(prv == CKR_FUNCTION_NOT_SUPPORTED,                               \
          "%s: GetOperationState stub pinned", tag);                       \
    /* stub-beats-args -- NULL/garbage args to stubs yield  */ \
    /* the stub code on every table (uniform stub-first). Direct-only:   */ \
    /* the proxy shim interposes its own forwarding behavior, so these   */ \
    /* pins assert our module's contract, not the shim's. */                 \
    if (!isProxy) {                                                          \
      prv = (T)->C_InitToken(99, NULL_PTR, 0xFFFFFFFFUL, NULL_PTR);          \
      CHECKC(prv == CKR_FUNCTION_NOT_SUPPORTED,                               \
            "%s: stub-beats-args init-token", tag);                           \
      prv = (T)->C_SetPIN(0xFFFFFFFFUL, NULL_PTR, 0, NULL_PTR, 0);           \
      CHECKC(prv == CKR_FUNCTION_NOT_SUPPORTED,                               \
            "%s: stub-beats-args set-pin", tag);                              \
    }                                                                        \
    prv = (T)->C_CloseSession(sess);                                       \
    CHECKC(prv == CKR_OK, "%s: session closes", tag);                       \
    sess = 0;                                                              \
  } while (0)

static CK_FUNCTION_LIST_PTR g_legacy = NULL_PTR;
static CK_FUNCTION_LIST_3_0_PTR g_t30 = NULL_PTR;
static CK_FUNCTION_LIST_3_0_PTR g_t31 = NULL_PTR;
static CK_FUNCTION_LIST_3_2_PTR g_t32 = NULL_PTR;

/* Open on slot 0, falling back to the first listed slot (mirrors the
 * streaming consumer). */
static CK_RV open_session_on_legacy(CK_FUNCTION_LIST_PTR T,
                                    CK_SESSION_HANDLE *sess) {
  CK_RV prv = T->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, sess);
  if (prv == CKR_SLOT_ID_INVALID) {
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (T->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
      prv = T->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL_PTR, NULL_PTR, sess);
    }
  }
  return prv;
}

static CK_RV open_session_on_30(CK_FUNCTION_LIST_3_0_PTR T,
                                CK_SESSION_HANDLE *sess) {
  CK_RV prv = T->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, sess);
  if (prv == CKR_SLOT_ID_INVALID) {
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (T->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
      prv = T->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL_PTR, NULL_PTR, sess);
    }
  }
  return prv;
}

static CK_RV open_session_on_32(CK_FUNCTION_LIST_3_2_PTR T,
                                CK_SESSION_HANDLE *sess) {
  CK_RV prv = T->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, sess);
  if (prv == CKR_SLOT_ID_INVALID) {
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (T->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
      prv = T->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL_PTR, NULL_PTR, sess);
    }
  }
  return prv;
}

/* open_session_on dispatches on the table pointer identity. */
static CK_RV open_session_on(void *T, CK_SESSION_HANDLE *sess) {
  if (T == (void *)g_legacy) {
    return open_session_on_legacy(g_legacy, sess);
  }
  if (T == (void *)g_t30) {
    return open_session_on_30(g_t30, sess);
  }
  if (T == (void *)g_t31) {
    return open_session_on_30(g_t31, sess);
  }
  return open_session_on_32(g_t32, sess);
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_C_GetInterfaceList pGetInterfaceList;
  CK_C_GetInterface pGetInterface;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_INTERFACE_PTR p32 = NULL_PTR, p31 = NULL_PTR, p30 = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  CK_SESSION_HANDLE lsess = 0;
  const char *topo;
  int isProxy;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  pGetInterfaceList =
      (CK_C_GetInterfaceList)dlsym(handle, "C_GetInterfaceList");
  pGetInterface = (CK_C_GetInterface)dlsym(handle, "C_GetInterface");
  CHECK(pGetList && pGetInterfaceList && pGetInterface,
        "discovery symbols resolve");

  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p32, 0);
  CHECK(rv == CKR_OK && p32 != NULL_PTR, "GetInterface selects 3.2");
  v.minor = 1;
  p31 = NULL_PTR;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p31, 0);
  if (!isProxy) {
    CHECKM(rv == CKR_OK && p31 != NULL_PTR, "GetInterface selects 3.1");
  } else {
    CHECKM(rv == CKR_OK && p31 == NULL_PTR,
           "GetInterface 3.1 misses NULL (no shim 3.1)");
  }
  v.minor = 0;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p30, 0);
  CHECK(rv == CKR_OK && p30 != NULL_PTR, "GetInterface selects 3.0");
  if (p32 != NULL_PTR) {
    g_t32 = (CK_FUNCTION_LIST_3_2_PTR)p32->pFunctionList;
  }
  if (p31 != NULL_PTR) {
    g_t31 = (CK_FUNCTION_LIST_3_0_PTR)p31->pFunctionList;
  }
  if (p30 != NULL_PTR) {
    g_t30 = (CK_FUNCTION_LIST_3_0_PTR)p30->pFunctionList;
  }
  rv = pGetList(&legacy);
  CHECK(rv == CKR_OK && legacy, "legacy GetFunctionList resolves");
  CHECK(legacy->version.major == 2 && legacy->version.minor == 40,
        "legacy table version is 2.40");
  g_legacy = legacy;
  CHECK(g_t32 && g_t30, "3.2 and 3.0 tables selected");
  if (!g_t32 || !g_t30 || !legacy) {
    printf("FAIL: required tables missing; aborting\n");
    return 1;
  }

  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "legacy C_Initialize ok");

  ERRORS_SCENARIO("2.40", legacy);
  ERRORS_SCENARIO("3.0", g_t30);
  if (g_t31 != NULL_PTR) {
    ERRORS_SCENARIO("3.1", g_t31);
  }
  ERRORS_SCENARIO("3.2", g_t32);

  /* Login probes once: token auth state is shared across tables. */
  rv = open_session_on_legacy(legacy, &lsess);
  CHECK(rv == CKR_OK && lsess != 0, "login session opens");
  rv = legacy->C_Logout(lsess);
  CHECK(rv == CKR_USER_NOT_LOGGED_IN, "logout without login refused");
  rv = legacy->C_Login(lsess, CKU_USER, (CK_UTF8CHAR_PTR) "9999", 4);
  CHECK(rv == CKR_PIN_INCORRECT, "wrong PIN incorrect");
  rv = legacy->C_Login(lsess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
  CHECK(rv == CKR_OK, "correct PIN after a miss");
  rv = legacy->C_Logout(lsess);
  CHECK(rv == CKR_OK, "logout ok");
  rv = legacy->C_CloseSession(lsess);
  CHECK(rv == CKR_OK, "login session closes");

  /* 3.x-only stub (C_LoginUser), garbage args, stub code
   * wins. Direct-only, invent:-scoped like the 3.1 lines: the shim
   * interposes its own behavior, so this asserts our module's
   * contract and stays out of the parity transcript. */
  if (!isProxy) {
    rv = g_t30->C_LoginUser(0xFFFFFFFFUL, 0xFF, NULL_PTR, 0xFFFFFFFFUL,
                            NULL_PTR, 0xFFFFFFFFUL);
    CHECKM(rv == CKR_FUNCTION_NOT_SUPPORTED,
           "stub-beats-args login-user (3.0)");
  }

  rv = legacy->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("PASS: consumer_errors (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
