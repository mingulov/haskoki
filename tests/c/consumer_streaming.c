/* tests/c/consumer_streaming.c — streaming multipart proof:
 * digest Init/Update/Final over the legacy 2.40 + 3.x tables:
 *   - small multipart ("hello, world") matches its KAT
 *   - 8 MiB in 64 KiB parts matches its KAT (under the 16 MiB
 *     bound: buffered plans complete this too)
 *   - 1 MiB stream matches its KAT plus a one-shot cross-check on
 *     a second session (kept under the proxy's 4 MiB default
 *     message cap so the cross-check runs in both topologies)
 *   - 20 MiB in 64 KiB parts matches its KAT (over the 16 MiB
 *     per-buffer bound: only the streamed path completes this; the
 *     buffered planner refuses part 257 with CKR_ARGUMENTS_BAD)
 *   - abort: closing a session mid-stream succeeds and a fresh
 *     digest on a new session works (no session-poisoning)
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module (or, in proxy topology, the pkcs11-proxy-ng
 * shim) and drives it through the pinned 3.2 headers.
 *
 * Topology: HASKOKI_CONSUMER_TOPOLOGY=proxy selects proxy-mode
 * expectations (no 3.1 table behind the shim). Lines prefixed
 * "crypto:" carry per-table digest assertions; all other check lines
 * carry topology-independent assertions, and the parity script diffs
 * exactly those lines direct-vs-proxied.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_streaming <path-to-libhaskoki.so>
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

/* Topology-scoped checks: prefixed so the parity script excludes them
 * (handle-carrying calls legitimately diverge: the backend answers
 * from its direct path while the shim rejects unopened handles first). */
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

/* KATs: SHA-256 over the deterministic pattern byte[i] = (i*31+7)&0xFF
 * (1 MiB / 8 MiB / 20 MiB), plus SHA-256("hello, world") and
 * SHA-256("abc"). */
static const CK_BYTE k1M[32] = {
  0x06, 0xb7, 0xbb, 0xfb, 0x78, 0x24, 0xaa, 0x03, 0x38, 0x20, 0x51, 0x69,
  0x16, 0x30, 0xeb, 0x26, 0xde, 0x85, 0x10, 0x2d, 0x1b, 0x08, 0xa8, 0x1e,
  0x90, 0x7e, 0xc0, 0x74, 0x4c, 0xd8, 0xa2, 0x86
};
static const CK_BYTE kHello[32] = {
  0x09, 0xca, 0x7e, 0x4e, 0xaa, 0x6e, 0x8a, 0xe9, 0xc7, 0xd2, 0x61, 0x16,
  0x71, 0x29, 0x18, 0x48, 0x83, 0x64, 0x4d, 0x07, 0xdf, 0xba, 0x7c, 0xbf,
  0xbc, 0x4c, 0x8a, 0x2e, 0x08, 0x36, 0x0d, 0x5b
};
static const CK_BYTE k8M[32] = {
  0x0f, 0xf4, 0xd6, 0xc0, 0x68, 0xbe, 0x24, 0x63, 0x7e, 0x84, 0xea, 0x9f,
  0x48, 0x1c, 0x3c, 0x29, 0xf7, 0xaf, 0xcd, 0xef, 0x1e, 0x06, 0xe1, 0xf4,
  0x0a, 0x68, 0xe5, 0xde, 0x85, 0xdc, 0xbb, 0x5b
};
static const CK_BYTE k20M[32] = {
  0x3f, 0x09, 0x51, 0x1f, 0x94, 0xe2, 0x98, 0xb2, 0x2e, 0xd7, 0x6f, 0xd0,
  0x36, 0x1c, 0x1c, 0x5b, 0x3a, 0x23, 0x83, 0xaf, 0x38, 0x79, 0x3d, 0x37,
  0x14, 0x65, 0xe5, 0x07, 0x0e, 0xc8, 0xf3, 0x56
};
static const CK_BYTE kAbc[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

#define PART_LEN (64u * 1024u)
#define LEN_1M (1u * 1024u * 1024u)
#define LEN_8M (8u * 1024u * 1024u)
#define LEN_20M (20u * 1024u * 1024u)

static CK_BYTE *g_buf8 = NULL;
static CK_BYTE *g_buf20 = NULL;

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
  char tmpl[] = "/tmp/haskoki-streaming-XXXXXX";
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

static void fill_pattern(CK_BYTE *buf, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    buf[i] = (CK_BYTE)((i * 31u + 7u) & 0xFFu);
  }
}

/* The streaming scenario, instantiated once per available table. The
 * table expression has that table's own type, so each table's real
 * entry points are exercised. */
#define STREAM_SCENARIO(tag, T)                                            \
  do {                                                                     \
    CK_SESSION_HANDLE sess = 0;                                            \
    CK_SESSION_HANDLE sess2 = 0;                                           \
    CK_MECHANISM mech;                                                     \
    CK_BYTE out[64];                                                       \
    CK_BYTE cross[64];                                                     \
    CK_ULONG outLen;                                                       \
    CK_ULONG crossLen;                                                     \
    CK_RV prv;                                                             \
    size_t off;                                                            \
    mech.mechanism = CKM_SHA256;                                           \
    mech.pParameter = NULL_PTR;                                            \
    mech.ulParameterLen = 0;                                               \
    prv = (T)->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,       \
                             NULL_PTR, NULL_PTR, &sess);                   \
    if (prv == CKR_SLOT_ID_INVALID) {                                      \
      CK_SLOT_ID psl[8];                                                   \
      CK_ULONG pn = 8;                                                     \
      if ((T)->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {           \
        prv = (T)->C_OpenSession(psl[0],                                   \
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,      \
                                 NULL_PTR, NULL_PTR, &sess);               \
      }                                                                    \
    }                                                                      \
    CHECKC(prv == CKR_OK && sess != 0, "%s: session opens", tag);           \
    /* small multipart == KAT */                                           \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: small DigestInit ok", tag);                 \
    prv = (T)->C_DigestUpdate(sess, (CK_BYTE_PTR) "hello, ", 7);           \
    CHECKC(prv == CKR_OK, "%s: small update 1 ok", tag);                   \
    prv = (T)->C_DigestUpdate(sess, (CK_BYTE_PTR) "world", 5);             \
    CHECKC(prv == CKR_OK, "%s: small update 2 ok", tag);                   \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_OK && outLen == 32 && memcmp(out, kHello, 32) == 0,   \
           "%s: small multipart matches KAT", tag);                        \
    /* 8 MiB stream + KAT */                                                \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: 8M DigestInit ok", tag);                    \
    for (off = 0; off < LEN_8M; off += PART_LEN) {                         \
      prv = (T)->C_DigestUpdate(sess, g_buf8 + off, PART_LEN);              \
      if (prv != CKR_OK) {                                                 \
        break;                                                             \
      }                                                                    \
    }                                                                      \
    CHECKC(prv == CKR_OK && off == LEN_8M, "%s: 8M streams in parts", tag); \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_OK && outLen == 32 && memcmp(out, k8M, 32) == 0,      \
           "%s: 8M stream matches KAT", tag);                              \
    prv = (T)->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,       \
                             NULL_PTR, NULL_PTR, &sess2);                  \
    if (prv == CKR_SLOT_ID_INVALID) {                                      \
      CK_SLOT_ID psl[8];                                                   \
      CK_ULONG pn = 8;                                                     \
      if ((T)->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {           \
        prv = (T)->C_OpenSession(psl[0],                                   \
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,      \
                                 NULL_PTR, NULL_PTR, &sess2);              \
      }                                                                    \
    }                                                                      \
    /* 1 MiB stream + KAT + one-shot cross-check (under the proxy cap) */  \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: 1M DigestInit ok", tag);                    \
    for (off = 0; off < LEN_1M; off += PART_LEN) {                         \
      prv = (T)->C_DigestUpdate(sess, g_buf8 + off, PART_LEN);              \
      if (prv != CKR_OK) {                                                 \
        break;                                                             \
      }                                                                    \
    }                                                                      \
    CHECKC(prv == CKR_OK && off == LEN_1M, "%s: 1M streams in parts", tag); \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_OK && outLen == 32 && memcmp(out, k1M, 32) == 0,      \
           "%s: 1M stream matches KAT", tag);                              \
    CHECKC(prv == CKR_OK && sess2 != 0, "%s: cross session opens", tag);   \
    prv = (T)->C_DigestInit(sess2, &mech);                                 \
    CHECKC(prv == CKR_OK, "%s: cross DigestInit ok", tag);                 \
    crossLen = sizeof(cross);                                              \
    prv = (T)->C_Digest(sess2, g_buf8, LEN_1M, cross, &crossLen);           \
    CHECKC(prv == CKR_OK && crossLen == 32 &&                              \
               memcmp(cross, out, 32) == 0,                                \
           "%s: 1M one-shot cross-checks the stream", tag);                \
    prv = (T)->C_CloseSession(sess2);                                      \
    CHECKC(prv == CKR_OK, "%s: cross session closes", tag);                \
    sess2 = 0;                                                             \
    /* 20 MiB stream: over the 16 MiB bound, KAT-checked */                \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: 20M DigestInit ok", tag);                   \
    for (off = 0; off < LEN_20M; off += PART_LEN) {                        \
      prv = (T)->C_DigestUpdate(sess, g_buf20 + off, PART_LEN);             \
      if (prv != CKR_OK) {                                                 \
        break;                                                             \
      }                                                                    \
    }                                                                      \
    CHECKC(prv == CKR_OK && off == LEN_20M,                                \
           "%s: 20M streams past the bound", tag);                         \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_DigestFinal(sess, out, &outLen);                          \
    CHECKC(prv == CKR_OK && outLen == 32 && memcmp(out, k20M, 32) == 0,     \
           "%s: 20M stream matches KAT", tag);                             \
    /* abort: close mid-stream, then a fresh digest works */               \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: abort DigestInit ok", tag);                 \
    prv = (T)->C_DigestUpdate(sess, (CK_BYTE_PTR) "abc", 3);               \
    CHECKC(prv == CKR_OK, "%s: abort update ok", tag);                     \
    prv = (T)->C_CloseSession(sess);                                       \
    CHECKC(prv == CKR_OK, "%s: close mid-stream ok", tag);                 \
    sess = 0;                                                              \
    prv = (T)->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,       \
                             NULL_PTR, NULL_PTR, &sess);                   \
    if (prv == CKR_SLOT_ID_INVALID) {                                      \
      CK_SLOT_ID psl[8];                                                   \
      CK_ULONG pn = 8;                                                     \
      if ((T)->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {           \
        prv = (T)->C_OpenSession(psl[0],                                   \
                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,      \
                                 NULL_PTR, NULL_PTR, &sess);               \
      }                                                                    \
    }                                                                      \
    CHECKC(prv == CKR_OK && sess != 0, "%s: post-abort session opens",     \
           tag);                                                           \
    prv = (T)->C_DigestInit(sess, &mech);                                  \
    CHECKC(prv == CKR_OK, "%s: post-abort DigestInit ok", tag);            \
    outLen = sizeof(out);                                                  \
    prv = (T)->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, out, &outLen);       \
    CHECKC(prv == CKR_OK && outLen == 32 && memcmp(out, kAbc, 32) == 0,     \
           "%s: post-abort one-shot keeps FIPS bytes", tag);               \
    prv = (T)->C_CloseSession(sess);                                       \
    CHECKC(prv == CKR_OK, "%s: post-abort session closes", tag);           \
    sess = 0;                                                              \
  } while (0)

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_C_GetInterfaceList pGetInterfaceList;
  CK_C_GetInterface pGetInterface;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_INTERFACE_PTR p32 = NULL_PTR, p31 = NULL_PTR, p30 = NULL_PTR;
  CK_FUNCTION_LIST_3_2_PTR tbl32 = NULL_PTR;
  CK_FUNCTION_LIST_3_0_PTR tbl31 = NULL_PTR, tbl30 = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
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
  g_buf8 = (CK_BYTE_PTR)malloc(LEN_8M);
  g_buf20 = (CK_BYTE_PTR)malloc(LEN_20M);
  if (!g_buf8 || !g_buf20) {
    fprintf(stderr, "stream buffers did not allocate\n");
    return 2;
  }
  fill_pattern(g_buf8, LEN_8M);
  fill_pattern(g_buf20, LEN_20M);
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

  /* ---- tables (3.1 exists direct-only; the shim has no 3.1) ---- */
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
    tbl32 = (CK_FUNCTION_LIST_3_2_PTR)p32->pFunctionList;
  }
  if (p31 != NULL_PTR) {
    tbl31 = (CK_FUNCTION_LIST_3_0_PTR)p31->pFunctionList;
  }
  if (p30 != NULL_PTR) {
    tbl30 = (CK_FUNCTION_LIST_3_0_PTR)p30->pFunctionList;
  }
  rv = pGetList(&legacy);
  CHECK(rv == CKR_OK && legacy, "legacy GetFunctionList resolves");
  CHECK(legacy->version.major == 2 && legacy->version.minor == 40,
        "legacy table version is 2.40");
  CHECK(tbl32 && tbl30, "3.2 and 3.0 tables selected");
  if (!tbl32 || !tbl30 || !legacy) {
    printf("FAIL: required tables missing; aborting\n");
    return 1;
  }

  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "legacy C_Initialize ok");

  STREAM_SCENARIO("2.40", legacy);
  STREAM_SCENARIO("3.0", tbl30);
  if (tbl31 != NULL_PTR) {
    STREAM_SCENARIO("3.1", tbl31);
  }
  STREAM_SCENARIO("3.2", tbl32);

  rv = legacy->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  rv = legacy->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "post-finalize OpenSession needs init (state first)");

  dlclose(handle);
  unlink(g_cfg_path);
  free(g_buf8);
  free(g_buf20);
  if (g_failures == 0) {
    printf("PASS: consumer_streaming (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
