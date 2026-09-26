/* tests/c/release_smoke.c — release install smoke test.
 *
 * Standalone C program (non-Haskell executable): dlopen()s an
 * INSTALLED libhaskoki.so (resolving its GHC closure from the
 * artifact lib/ dir via the module's own $ORIGIN RUNPATH with
 * LD_LIBRARY_PATH unset, never from a toolchain)
 * and runs the install-acceptance slice over the FULL served
 * surface (demo-maximal per the product ruling — assert everything
 * actually served):
 * discovery, init, metadata, token presence, the EXACT served
 * mechanism catalog (count + CKM_SHA256 membership), two REAL
 * session lifecycles each yielding REAL SHA-256 one-shot
 * FIPS 180-4 "abc" bytes, finalize. Exit 0 + SMOKE-OK iff every
 * check passes.
 *
 * Served-count provenance (measured, never assumed): at commit
 * 03ea925 a minimal size-query probe against the release artifact
 * reports size-query n=130, full-list n=130, sha256-member=1;
 * the count is the support.real == "tested"
 * projection of spec/mechanisms.json (130 rows) frozen into
 * cbits/mech_catalog.inc (HASKOKI_MECH_COUNT 130) and
 * independently pinned by tests/c/consumer_discovery.c (two "has
 * 130 rows" legs plus size-query and short-buffer legs).
 *
 * Bundled into the release artifact with the pinned 2.40 headers
 * (self-contained: cc release_smoke.c -Iinclude -ldl) and also
 * compilable from the repo (-Ispec/vendor).
 * Part of scripts/test-release-install.sh.
 * Usage: release_smoke <path-to-installed-libhaskoki.so>
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

/* EXACT served mechanism count (provenance in the header above). */
#define SMOKE_MECH_COUNT 130

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("SMOKE-FAIL [%s:%d]: ", __FILE__, __LINE__);                  \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("smoke-ok: ");                                                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

static const CK_BYTE kWant[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

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
  char tmpl[] = "/tmp/haskoki-smoke-XXXXXX";
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

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f = NULL_PTR;
  CK_RV rv;
  CK_INFO info;
  CK_SLOT_ID slots[8];
  CK_ULONG n = 8;
  CK_TOKEN_INFO tinfo;
  CK_MECHANISM_TYPE mechs[SMOKE_MECH_COUNT];
  CK_MECHANISM mech;
  CK_SESSION_HANDLE sess = 0;
  CK_SESSION_HANDLE sess2 = 0;
  CK_BYTE out[64];
  CK_ULONG outLen;
  CK_ULONG q = 0;
  CK_ULONG i = 0;
  int have256 = 0;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    printf("SMOKE-FAIL dlopen: %s\n", dlerror());
    return 1;
  }
  CHECK(1, "dlopen resolves full closure (no missing libs)");
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != NULL, "C_GetFunctionList resolves");
  rv = pGetList(&f);
  CHECK(rv == CKR_OK && f, "function list fetches");
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok (RTS boots, config loads)");
  memset(&info, 0, sizeof(info));
  rv = f->C_GetInfo(&info);
  CHECK(rv == CKR_OK && info.libraryVersion.major == 0 &&
            info.libraryVersion.minor == 3,
        "C_GetInfo reports lib 0.3");
  n = 8;
  rv = f->C_GetSlotList(0, slots, &n);
  CHECK(rv == CKR_OK && n == 1, "one slot enumerated");
  memset(&tinfo, 0, sizeof(tinfo));
  rv = f->C_GetTokenInfo(slots[0], &tinfo);
  CHECK(rv == CKR_OK && memcmp(tinfo.label, "haskoki-demo", 12) == 0 &&
            memcmp(tinfo.manufacturerID, "haskoki contributors", 20) == 0 &&
            memcmp(tinfo.model, "soft-token", 10) == 0 &&
            (tinfo.flags & CKF_TOKEN_INITIALIZED) != 0 &&
            (tinfo.flags & CKF_USER_PIN_INITIALIZED) != 0 &&
            (tinfo.flags & CKF_LOGIN_REQUIRED) != 0,
        "token present: pinned label/manufacturer/model/flags");
  rv = f->C_GetMechanismList(slots[0], NULL_PTR, &q);
  CHECK(rv == CKR_OK && q == SMOKE_MECH_COUNT,
        "mechanism size-query reports %lu (want %d)", (unsigned long)q,
        SMOKE_MECH_COUNT);
  n = SMOKE_MECH_COUNT;
  rv = f->C_GetMechanismList(slots[0], mechs, &n);
  CHECK(rv == CKR_OK && n == SMOKE_MECH_COUNT,
        "mechanism list serves %lu rows (want %d)", (unsigned long)n,
        SMOKE_MECH_COUNT);
  for (i = 0; i < n; i++) {
    if (mechs[i] == CKM_SHA256) {
      have256 = 1;
    }
  }
  CHECK(have256, "mechanism list contains CKM_SHA256");
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK && sess != 0, "first session opens");
  rv = f->C_DigestInit(sess, &mech);
  CHECK(rv == CKR_OK, "first DigestInit ok (real session)");
  outLen = sizeof(out);
  rv = f->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
  CHECK(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
        "first one-shot digest yields FIPS bytes");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "first session closes");
  sess = 0;
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess2);
  CHECK(rv == CKR_OK && sess2 != 0, "second session opens (independence)");
  rv = f->C_DigestInit(sess2, &mech);
  CHECK(rv == CKR_OK, "second DigestInit ok");
  outLen = sizeof(out);
  rv = f->C_Digest(sess2, (CK_BYTE_PTR) "abc", 3, out, &outLen);
  CHECK(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
        "second one-shot digest yields FIPS bytes");
  rv = f->C_CloseSession(sess2);
  CHECK(rv == CKR_OK, "second session closes");
  sess2 = 0;
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("SMOKE-OK: release_smoke (%s)\n", argv[1]);
    return 0;
  }
  printf("SMOKE-FAILURES: %d\n", g_failures);
  return 1;
}
