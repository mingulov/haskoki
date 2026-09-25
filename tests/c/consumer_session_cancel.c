/* tests/c/consumer_session_cancel.c -- C_SessionCancel live-behavior pins.
 *
 * Drives the real C_SessionCancel table slot (3.2 and 3.0 tables) through
 * the built shared module: cancel clears CKR_OPERATION_ACTIVE so the
 * session re-inits clean (the MCT recovery path), selective masks keep
 * unselected operations, and unknown sessions refuse.
 *
 * Scenario per table (CKM_SHA256 digest, no key required):
 *   - C_DigestInit OK; second C_DigestInit is CKR_OPERATION_ACTIVE
 *   - C_SessionCancel(CKF_ENCRYPT) OK; digest still active
 *     (second init still CKR_OPERATION_ACTIVE)
 *   - C_SessionCancel(CKF_DIGEST) OK; C_DigestInit OK again
 *   - C_SessionCancel(0) with an active op OK; C_DigestInit OK again
 *   - C_SessionCancel(0) idle OK (idempotent no-op)
 *   - C_SessionCancel(unknown session) is CKR_SESSION_HANDLE_INVALID
 *
 * Pre-init C_SessionCancel (NOT_INITIALIZED) stays pinned by the
 * layout probes (tests/c/layout_300.c, layout_310.c).
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2
 * headers. Scenario lines carry "crypto:" (excluded from the proxy
 * parity diff; asserted strictly per mode). Proxy mode NULL-guards
 * the 3.x slot: a shim without C_SessionCancel skips via "invent:".
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_session_cancel <path-to-libhaskoki.so>
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
static int g_isProxy = 0;

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
  char tmpl[] = "/tmp/haskoki-cancel-XXXXXX";
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

/* The cancel scenario over raw function pointers, so one body covers
 * the 3.0 and 3.2 table layouts. */
typedef CK_RV (*fn_open_session)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR,
                                CK_NOTIFY, CK_SESSION_HANDLE_PTR);
typedef CK_RV (*fn_close_session)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_digest_init)(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                           CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*fn_cancel)(CK_SESSION_HANDLE, CK_FLAGS);

static void run_cancel_scenario(const char *tag, fn_open_session pOpen,
                                fn_close_session pClose,
                                fn_digest_init pDigestInit, fn_digest pDigest,
                                fn_cancel pCancel) {
  CK_SESSION_HANDLE sess = 0;
  CK_MECHANISM mech;
  CK_RV rv;
  CK_BYTE digest[64];
  CK_ULONG digestLen = sizeof(digest);
  static const CK_BYTE input[] = "cancel me";

  if (pCancel == NULL) {
    CHECKM(g_isProxy, "%s: NULL cancel slot only behind the shim", tag);
    return;
  }
  CHECKC(pCancel != NULL, "%s: cancel slot wired", tag);

  rv = pOpen(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
             &sess);
  CHECKC(rv == CKR_OK, "%s: session opens", tag);
  if (rv != CKR_OK) {
    return;
  }
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;

  /* Occupancy: the second init reports the active operation. */
  rv = pDigestInit(sess, &mech);
  CHECKC(rv == CKR_OK, "%s: digest inits", tag);
  rv = pDigestInit(sess, &mech);
  CHECKC(rv == CKR_OPERATION_ACTIVE, "%s: second init is active", tag);

  /* Selective cancel keeps the unselected digest. */
  rv = pCancel(sess, CKF_ENCRYPT);
  CHECKC(rv == CKR_OK, "%s: selective cancel ok", tag);
  rv = pDigestInit(sess, &mech);
  CHECKC(rv == CKR_OPERATION_ACTIVE, "%s: digest survives encrypt mask",
         tag);

  /* Selective cancel clears the selected digest. */
  rv = pCancel(sess, CKF_DIGEST);
  CHECKC(rv == CKR_OK, "%s: digest-mask cancel ok", tag);
  rv = pDigestInit(sess, &mech);
  CHECKC(rv == CKR_OK, "%s: digest re-inits after cancel", tag);

  /* Zero mask cancels everything (recovery semantic). */
  rv = pCancel(sess, 0);
  CHECKC(rv == CKR_OK, "%s: zero-mask cancel ok", tag);
  rv = pDigestInit(sess, &mech);
  CHECKC(rv == CKR_OK, "%s: digest re-inits after zero-mask", tag);

  /* Idle cancel is a no-op OK: conclude the digest, then cancel. */
  digestLen = sizeof(digest);
  rv = pDigest(sess, (CK_BYTE_PTR)input, sizeof(input) - 1, digest,
               &digestLen);
  CHECKC(rv == CKR_OK, "%s: one-shot digest ok", tag);
  rv = pCancel(sess, 0);
  CHECKC(rv == CKR_OK, "%s: idle cancel ok", tag);

  /* Unknown sessions refuse. */
  rv = pCancel(0xFFFFFFFFUL, 0);
  CHECKC(rv == CKR_SESSION_HANDLE_INVALID, "%s: unknown session refuses",
         tag);

  rv = pClose(sess);
  CHECKC(rv == CKR_OK, "%s: session closes", tag);
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_C_GetInterface pGetInterface;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_FUNCTION_LIST_3_0_PTR t30 = NULL_PTR;
  CK_FUNCTION_LIST_3_2_PTR t32 = NULL_PTR;
  CK_INTERFACE_PTR pIf = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  const char *topo;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  g_isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", g_isProxy ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  pGetInterface = (CK_C_GetInterface)dlsym(handle, "C_GetInterface");
  CHECK(pGetList && pGetInterface, "discovery symbols resolve");
  if (!pGetList || !pGetInterface) {
    return 2;
  }
  rv = pGetList(&legacy);
  CHECK(rv == CKR_OK && legacy != NULL_PTR, "legacy table fetched");
  if (!legacy) {
    return 2;
  }

  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &pIf, 0);
  CHECK(rv == CKR_OK && pIf != NULL_PTR, "GetInterface selects 3.2");
  if (pIf != NULL_PTR) {
    t32 = (CK_FUNCTION_LIST_3_2_PTR)pIf->pFunctionList;
  }
  pIf = NULL_PTR;
  v.minor = 0;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &pIf, 0);
  CHECK(rv == CKR_OK && pIf != NULL_PTR, "GetInterface selects 3.0");
  if (pIf != NULL_PTR) {
    t30 = (CK_FUNCTION_LIST_3_0_PTR)pIf->pFunctionList;
  }
  if (!t32 || !t30) {
    return 2;
  }

  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok (rv=%lu)",
        (unsigned long)rv);
  if (rv != CKR_OK) {
    return 2;
  }

  run_cancel_scenario("3.2", t32->C_OpenSession, t32->C_CloseSession,
                      t32->C_DigestInit, t32->C_Digest, t32->C_SessionCancel);
  run_cancel_scenario("3.0", t30->C_OpenSession, t30->C_CloseSession,
                      t30->C_DigestInit, t30->C_Digest, t30->C_SessionCancel);

  rv = t32->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");

  unlink(g_cfg_path);
  if (g_failures) {
    printf("FAIL: %d check(s) failed\n", g_failures);
    return 1;
  }
  printf("PASS: session-cancel consumer\n");
  return 0;
}
