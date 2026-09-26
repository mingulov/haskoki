/* tests/c/consumer_roundtrip.c — direct-load consumer, fully wired:
 * real session/object/sign/encrypt round-trips plus pinned refusals
 * for the genuinely unrouted calls.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module (or, in proxy topology, the pkcs11-proxy-ng
 * shim) and drives it through the pinned 3.2 headers:
 *   - REAL digest round-trips via the routed engine:
 *     one-shot/size-query/short-buffer recall over SHA-256, SHA-1
 *     and SHA-512 (FIPS "abc" bytes), multipart update/final flows,
 *     and init/update/final edge codes, on a real session in both
 *     topologies
 *   - the SAME bytes via the routed haskoki_crypto_* trampolines
 *     (Haskell engine path; prototypes redeclared locally, never from
 *     provider headers) and a byte cross-check between both paths
 *     (direct topology only; the shim has no vendor trampolines)
 *   - REAL session and object flows: create/get/
 *     copy/find/destroy incl. visibility, the find cursor, and edge
 *     codes
 *   - PINNED honest refusals for the genuinely unrouted calls
 *     (CKR_FUNCTION_NOT_SUPPORTED from the surviving stubs in
 *     cbits/function_tables.c): no phantom support is claimed, and
 *     any future wiring flips these pins loudly instead of silently
 *   - slot-event no-event behavior + post-finalize state-first ordering
 *
 * Topology: HASKOKI_CONSUMER_TOPOLOGY=proxy selects proxy-mode
 * expectations for handle-carrying calls (CKR_SESSION_HANDLE_INVALID
 * from shim-side session validation — the backend never sees these
 * calls) and skips the routed-trampoline section. Lines prefixed
 * "crypto:"/"routed:" carry topology-specific assertions; all other
 * check lines carry topology-independent assertions over forwarded
 * calls, and the parity script diffs exactly those lines
 * direct-vs-proxied.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_roundtrip <path-to-libhaskoki.so>
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

/* Routed-digest trampolines: locally declared prototypes (independent
 * consumer; this TU deliberately does NOT include cbits headers). */
typedef void *haskoki_crypto_ctx_t;
typedef haskoki_crypto_ctx_t (*fn_crypto_open)(void);
typedef void (*fn_crypto_close)(haskoki_crypto_ctx_t ctx);
typedef CK_RV (*fn_crypto_digest_init)(haskoki_crypto_ctx_t ctx,
                                      CK_SESSION_HANDLE hSession,
                                      CK_MECHANISM_TYPE mech,
                                      CK_BYTE_PTR pParams,
                                      CK_ULONG ulParamsLen);
typedef CK_RV (*fn_crypto_digest)(haskoki_crypto_ctx_t ctx,
                                 CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                 CK_BYTE_PTR pDigest,
                                 CK_ULONG_PTR pulDigestLen);

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

#define CHECKR(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("routed: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("routed: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* FIPS 180-4: SHA-256("abc"). */
static const CK_BYTE kWant[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static char g_cfg_path[256];

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static CK_ULONG hex_to_bytes(const char *hex, CK_BYTE *out, CK_ULONG outlen) {
  CK_ULONG i = 0, n = 0;
  while (hex[i] && hex[i + 1] && n < outlen) {
    int hi = hex_nibble(hex[i]), lo = hex_nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) break;
    out[n++] = (CK_BYTE)((hi << 4) | lo);
    i += 2;
  }
  return n;
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
  char tmpl[] = "/tmp/haskoki-consumer-XXXXXX";
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
  CK_MECHANISM mech;
  CK_BYTE out[64];
  CK_ULONG outLen;
  CK_BYTE routed[64];
  CK_ULONG routedLen;
  int routedRan = 0;
  fn_crypto_open pOpen;
  fn_crypto_close pClose;
  fn_crypto_digest_init pInit;
  fn_crypto_digest pDigest;
  haskoki_crypto_ctx_t ctx;
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
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != NULL, "C_GetFunctionList resolves");
  rv = pGetList(&f);
  CHECK(rv == CKR_OK && f, "function list fetches");
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok");

  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  /* ---- REAL digest via the routed engine: one-shot,
   * size-query, short-buffer recall, and multipart, on a real
   * session in both topologies (the shim forwards opened
   * handles). ---- */
  {
    static const CK_BYTE kWant1[20] = {
      0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
      0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
    };
    static const CK_BYTE kWant512[64] = {
      0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41,
      0x73, 0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e,
      0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
      0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
      0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d,
      0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
      0xa5, 0x4c, 0xa4, 0x9f
    };
    CK_SESSION_HANDLE dsess = 0;
    CK_BYTE big[64];
    CK_ULONG bigLen;
    rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &dsess);
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &dsess);
      }
    }
    CHECKC(rv == CKR_OK && dsess != 0, "digest session opens");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "digest without init is NOT_INITIALIZED");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "DigestInit SHA256 ok");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OPERATION_ACTIVE, "second DigestInit is ACTIVE");
    outLen = 0;
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32, "size query reports 32");
    /* A successful size query does not terminate the op (PKCS#11 v3.1
     * C_Digest: a call "to determine the length of the buffer needed"
     * leaves the operation live): the follow-up one-shot completes. */
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "one-shot after query completes with FIPS bytes");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "re-init after one-shot");
    outLen = 8;
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && outLen == 32,
           "short buffer reports 32");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "recall completes with FIPS bytes");
    /* A query finalizes the one-shot: updates refuse, but the staged
     * output stays for the recall. */
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "re-init for query-update edge");
    outLen = 0;
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32, "edge query reports 32");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "abc", 3);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "update after query is NOT_INITIALIZED");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "recall after refused update keeps FIPS bytes");
    /* A second size query re-reports the length; the op stays live. */
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "re-init for double query");
    outLen = 0;
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32, "first query reports 32");
    outLen = 0;
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32, "second query reports 32");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "one-shot after double query completes");
    rv = f->C_DigestInit(dsess, NULL_PTR);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "NULL mechanism is ARGUMENTS_BAD");
    mech.mechanism = 0xDEADUL;
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_MECHANISM_INVALID, "bogus init is MECHANISM_INVALID");
    mech.mechanism = CKM_SHA_1;
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "SHA-1 init ok (multi-digest)");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 20 && memcmp(out, kWant1, 20) == 0,
           "SHA-1 one-shot FIPS bytes");
    mech.mechanism = CKM_SHA512;
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "SHA-512 init ok");
    bigLen = sizeof(big);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, big, &bigLen);
    CHECKC(rv == CKR_OK && bigLen == 64 && memcmp(big, kWant512, 64) == 0,
           "SHA-512 one-shot FIPS bytes");
    mech.mechanism = CKM_SHA256;
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "update without init is NOT_INITIALIZED");
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "final without init is NOT_INITIALIZED");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "multipart init ok");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OK, "multipart update one ok");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "bc", 2);
    CHECKC(rv == CKR_OK, "multipart update two ok");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OPERATION_ACTIVE, "one-shot over buffered is ACTIVE");
    /* The refused one-shot terminates the op (spec: every error
     * other than BUFFER_TOO_SMALL terminates); a re-init follows. */
    outLen = sizeof(out);
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "final after refused one-shot is NOT_INITIALIZED");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "re-init after termination ok");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "abc", 3);
    CHECKC(rv == CKR_OK, "update after re-init ok");
    outLen = sizeof(out);
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "multipart final FIPS bytes");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "update after final is NOT_INITIALIZED");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "init for final-query");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "abc", 3);
    CHECKC(rv == CKR_OK, "update for final-query");
    outLen = 0;
    rv = f->C_DigestFinal(dsess, NULL_PTR, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32, "final query reports 32");
    outLen = sizeof(out);
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "final after query completes with FIPS bytes");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "init for short final");
    rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "abc", 3);
    CHECKC(rv == CKR_OK, "update for short final");
    outLen = 8;
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && outLen == 32,
           "short final reports 32");
    /* A second short call re-reports the required length. */
    outLen = 8;
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && outLen == 32,
           "second short final reports 32");
    outLen = sizeof(out);
    rv = f->C_DigestFinal(dsess, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32 && memcmp(out, kWant, 32) == 0,
           "final recall FIPS bytes");
    rv = f->C_DigestInit(dsess, &mech);
    CHECKC(rv == CKR_OK, "re-init after final");
    outLen = sizeof(out);
    rv = f->C_Digest(dsess, (CK_BYTE_PTR) "abc", 3, out, &outLen);
    CHECKC(rv == CKR_OK && outLen == 32, "terminating one-shot");
    {
      /* C_DigestKey feeds the secret value exactly like an update:
       * digest-of-key equals digest-of-extracted-value. */
      CK_OBJECT_HANDLE dkey = 0;
      CK_OBJECT_CLASS dcls = CKO_SECRET_KEY;
      CK_KEY_TYPE dkt = CKK_AES;
      CK_ULONG dlen = 16;
      CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
      CK_BYTE kval[32];
      CK_BYTE d1[64], d2[64];
      CK_ULONG d1Len, d2Len;
      CK_MECHANISM dkgm;
      CK_ATTRIBUTE dtmpl[] = {
        { CKA_CLASS, &dcls, sizeof(dcls) },
        { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
        { CKA_VALUE_LEN, &dlen, sizeof(dlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE vtmpl[] = {
        { CKA_VALUE, kval, sizeof(kval) }
      };
      dkgm.mechanism = CKM_AES_KEY_GEN;
      dkgm.pParameter = NULL_PTR;
      dkgm.ulParameterLen = 0;
      rv = f->C_GenerateKey(dsess, &dkgm, dtmpl, 6, &dkey);
      CHECKC(rv == CKR_OK && dkey != 0, "digest-key AES keygen ok");
      rv = f->C_DigestInit(dsess, &mech);
      CHECKC(rv == CKR_OK, "init for digest-key");
      rv = f->C_DigestKey(dsess, dkey);
      CHECKC(rv == CKR_OK, "digest-key feeds");
      d1Len = sizeof(d1);
      rv = f->C_DigestFinal(dsess, d1, &d1Len);
      CHECKC(rv == CKR_OK && d1Len == 32, "digest-key final ok");
      /* The op stays multipart-capable: key bytes mix with updates. */
      rv = f->C_DigestInit(dsess, &mech);
      CHECKC(rv == CKR_OK, "init for mixed feed");
      rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "pre", 3);
      CHECKC(rv == CKR_OK, "mixed update ok");
      rv = f->C_DigestKey(dsess, dkey);
      CHECKC(rv == CKR_OK, "mixed digest-key ok");
      rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "post", 4);
      CHECKC(rv == CKR_OK, "mixed trailing update ok");
      d2Len = sizeof(d2);
      rv = f->C_DigestFinal(dsess, d2, &d2Len);
      CHECKC(rv == CKR_OK && d2Len == 32, "mixed final ok");
      rv = f->C_GetAttributeValue(dsess, dkey, vtmpl, 1);
      CHECKC(rv == CKR_OK && vtmpl[0].ulValueLen == 16,
             "key value extracts");
      rv = f->C_DigestInit(dsess, &mech);
      CHECKC(rv == CKR_OK, "init for value comparison");
      rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "pre", 3);
      CHECKC(rv == CKR_OK, "comparison update ok");
      rv = f->C_DigestUpdate(dsess, kval, 16);
      CHECKC(rv == CKR_OK, "comparison value update ok");
      rv = f->C_DigestUpdate(dsess, (CK_BYTE_PTR) "post", 4);
      CHECKC(rv == CKR_OK, "comparison trailing update ok");
      d1Len = sizeof(d1);
      rv = f->C_DigestFinal(dsess, d1, &d1Len);
      CHECKC(rv == CKR_OK && d1Len == 32 &&
                 memcmp(d1, d2, 32) == 0,
             "digest-key equals digest-of-value");
      rv = f->C_DigestKey(dsess, dkey);
      CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
             "digest-key without init is NOT_INITIALIZED");
      rv = f->C_DigestInit(dsess, &mech);
      CHECKC(rv == CKR_OK, "init for bad-handle leg");
      rv = f->C_DigestKey(dsess, 0xFFFFFFFFUL);
      CHECKC(rv == CKR_OBJECT_HANDLE_INVALID,
             "digest-key bad handle is HANDLE_INVALID");
      rv = f->C_DigestInit(dsess, &mech);
      CHECKC(rv == CKR_OK, "re-init after bad handle ok (terminated)");
      rv = f->C_DestroyObject(dsess, dkey);
      CHECKC(rv == CKR_OK, "digest key destroys");
      d1Len = sizeof(d1);
      rv = f->C_DigestFinal(dsess, d1, &d1Len);
      CHECKC(rv == CKR_OK && d1Len == 32, "cleanup final ok");
    }
    {
      /* The engine recipe requires empty digest params
       * (checkMechParams): a stray param byte is ARGUMENTS_BAD. */
      CK_MECHANISM bad;
      CK_BYTE param = 0;
      bad.mechanism = CKM_SHA256;
      bad.pParameter = &param;
      bad.ulParameterLen = 1;
      rv = f->C_DigestInit(dsess, &bad);
      if (!isProxy) {
        CHECKC(rv == CKR_ARGUMENTS_BAD,
               "SHA-256 with stray param is ARGUMENTS_BAD");
      } else {
        /* The shim translates init param errors to PARAM_INVALID. */
        CHECKC(rv == CKR_MECHANISM_PARAM_INVALID,
               "proxied stray param is PARAM_INVALID");
      }
    }
    rv = f->C_CloseSession(dsess);
    CHECKC(rv == CKR_OK, "digest session closes");
  }

  /* ---- SAME bytes via the routed Haskell-engine trampolines ----
   * Direct topology only: the shim exports no vendor trampolines. */
  pOpen = (fn_crypto_open)dlsym(handle, "haskoki_crypto_open");
  pClose = (fn_crypto_close)dlsym(handle, "haskoki_crypto_close");
  pInit = (fn_crypto_digest_init)dlsym(handle, "haskoki_crypto_digest_init");
  pDigest = (fn_crypto_digest)dlsym(handle, "haskoki_crypto_digest");
  if (!pOpen || !pClose || !pInit || !pDigest) {
    if (!isProxy) {
      CHECKR(0, "routed trampolines resolve");
    } else {
      printf("routed: skip: shim has no vendor trampolines\n");
    }
  } else {
    ctx = pOpen();
    CHECKR(ctx != NULL, "routed ctx opens");
    if (ctx != NULL) {
      rv = pInit(ctx, 1, CKM_SHA256, NULL_PTR, 0);
      CHECKR(rv == CKR_OK, "routed digest init ok");
      routedLen = sizeof(routed);
      rv = pDigest(ctx, 1, (CK_BYTE_PTR) "abc", 3, routed, &routedLen);
      CHECKR(rv == CKR_OK && routedLen == 32 && memcmp(routed, kWant, 32) == 0,
             "routed digest yields FIPS bytes");
      routedRan = (rv == CKR_OK && routedLen == 32);
      pClose(ctx);
    }
  }
  if (!isProxy && routedRan) {
    CHECKR(memcmp(out, routed, 32) == 0,
           "C-surface and routed bytes agree");
  }

  /* ---- sessions are real; the rest stays pinned ----
   * Direct: sessions open/close against the routed engine; the calls
   * below still return CKR_FUNCTION_NOT_SUPPORTED from the remaining
   * stubs — no sessions meant no objects/login/keygen/sign/encrypt,
   * and now the survivors are exactly the genuinely unrouted calls.
   * Proxy: handle-free calls forward the same refusal; handle-
   * carrying calls are rejected pre-forward with
   * CKR_SESSION_HANDLE_INVALID (shim session validation). */
  rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                        NULL_PTR, &sess);
  if (rv == CKR_SLOT_ID_INVALID) {
    /* Proxy slot ids are remapped (observed: backend 0 -> proxy 1),
     * so retry with the discovered id when slot 0 misses. */
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
      rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
    }
  }
  CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok");
  rv = f->C_InitToken(0, (CK_UTF8CHAR_PTR) "5678", 4,
                      (CK_UTF8CHAR_PTR) "roundtrip");
  if (!isProxy) {
    CHECK(rv == CKR_FUNCTION_NOT_SUPPORTED, "InitToken honestly NA");
  } else {
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_InitToken(psl[0], (CK_UTF8CHAR_PTR) "5678", 4,
                            (CK_UTF8CHAR_PTR) "roundtrip");
      }
    }
    CHECK(rv == CKR_FUNCTION_NOT_SUPPORTED, "InitToken honestly NA");
  }
  /* ---- login/logout are real ---- */
  {
    CK_SESSION_INFO sinfo;
    CK_TOKEN_INFO tinf;
    CK_SLOT_ID here = 0;
    {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        here = psl[0];
      }
    }
    rv = f->C_GetSessionInfo(sess, &sinfo);
    CHECKC(rv == CKR_OK && sinfo.state == CKS_RW_PUBLIC_SESSION,
           "pre-login state public");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_OK, "user login ok");
    rv = f->C_GetSessionInfo(sess, &sinfo);
    CHECKC(rv == CKR_OK && sinfo.state == CKS_RW_USER_FUNCTIONS,
           "post-login state user");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_USER_ALREADY_LOGGED_IN, "double login refused");
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_OK, "logout ok");
    rv = f->C_GetSessionInfo(sess, &sinfo);
    CHECKC(rv == CKR_OK && sinfo.state == CKS_RW_PUBLIC_SESSION,
           "post-logout state public");
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_USER_NOT_LOGGED_IN, "logout without login refused");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "9999", 4);
    CHECKC(rv == CKR_PIN_INCORRECT, "wrong PIN incorrect");
    rv = f->C_GetTokenInfo(here, &tinf);
    CHECKC(rv == CKR_OK && (tinf.flags & CKF_USER_PIN_COUNT_LOW) != 0 &&
               (tinf.flags & CKF_USER_PIN_FINAL_TRY) == 0,
           "one miss shows count-low");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_OK, "correct PIN after a miss");
    rv = f->C_GetTokenInfo(here, &tinf);
    CHECKC(rv == CKR_OK && (tinf.flags & CKF_USER_PIN_COUNT_LOW) == 0,
           "success clears count-low");
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_OK, "logout before visibility flip");
    {
      CK_OBJECT_CLASS klass = CKO_DATA;
      CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
      CK_OBJECT_HANDLE priv = 0;
      CK_BYTE buf[64];
      CK_ATTRIBUTE ptmpl[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &no, sizeof(no) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, "s3-priv", 7 },
      };
      CK_ATTRIBUTE g[] = { { CKA_LABEL, buf, sizeof(buf) } };
      rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
      CHECKC(rv == CKR_OK, "login for visibility flip");
      rv = f->C_CreateObject(sess, ptmpl, 4, &priv);
      CHECKC(rv == CKR_OK && priv != 0, "private created while logged in");
      rv = f->C_GetAttributeValue(sess, priv, g, 1);
      CHECKC(rv == CKR_OK && g[0].ulValueLen == 7 &&
                 memcmp(buf, "s3-priv", 7) == 0,
             "private readable while logged in");
      rv = f->C_Logout(sess);
      CHECKC(rv == CKR_OK, "logout hides private");
      rv = f->C_GetAttributeValue(sess, priv, g, 1);
      CHECKC(rv == CKR_OBJECT_HANDLE_INVALID, "private hidden on logout");
      rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
      CHECKC(rv == CKR_OK, "re-login reveals private");
      rv = f->C_GetAttributeValue(sess, priv, g, 1);
      CHECKC(rv == CKR_OBJECT_HANDLE_INVALID,
             "logout-killed handle stays dead after re-login");
      {
        /* Re-find for a fresh handle: the object survived, only the
         * pre-logout binding died. */
        CK_OBJECT_HANDLE fresh[4];
        CK_ULONG nfresh = 4;
        CK_ATTRIBUTE match[] = { { CKA_LABEL, "s3-priv", 7 } };
        rv = f->C_FindObjectsInit(sess, match, 1);
        CHECKC(rv == CKR_OK, "re-find init after re-login");
        rv = f->C_FindObjects(sess, fresh, 4, &nfresh);
        CHECKC(rv == CKR_OK && nfresh == 1, "re-find yields one");
        rv = f->C_FindObjectsFinal(sess);
        CHECKC(rv == CKR_OK, "re-find final");
        priv = fresh[0];
      }
      rv = f->C_GetAttributeValue(sess, priv, g, 1);
      CHECKC(rv == CKR_OK && g[0].ulValueLen == 7, "private readable again");
      rv = f->C_DestroyObject(sess, priv);
      CHECKC(rv == CKR_OK, "private destroyed while logged in");
      rv = f->C_Logout(sess);
      CHECKC(rv == CKR_OK, "logout after visibility flip");
    }
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
    CHECKC(rv == CKR_OK, "SO login ok");
    rv = f->C_GetSessionInfo(sess, &sinfo);
    CHECKC(rv == CKR_OK && sinfo.state == CKS_RW_SO_FUNCTIONS,
           "SO session state");
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_OK, "SO logout ok");
    {
      CK_SESSION_HANDLE rosess = 0;
      rv = f->C_OpenSession(here, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                            &rosess);
      CHECKC(rv == CKR_OK && rosess != 0, "RO session for SO refusal");
      rv = f->C_Login(rosess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
      CHECKC(rv == CKR_SESSION_READ_ONLY_EXISTS, "SO on RO refused");
      rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
      CHECKC(rv == CKR_SESSION_READ_ONLY_EXISTS, "SO with RO open refused");
      rv = f->C_CloseSession(rosess);
      CHECKC(rv == CKR_OK, "RO session closed");
    }
    rv = f->C_Login(sess, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_USER_NOT_LOGGED_IN, "context login needs a user login");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_OK, "user login for context re-auth");
    rv = f->C_Login(sess, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "context re-auth needs an active op");
    {
      /* The op and the re-auth live on a scratch session: an
       * unspent context grant is spendable only on pending
       * always-authenticate slots, so finalizing the plain digest
       * here would refuse; closing the scratch session drops it. */
      CK_SESSION_HANDLE csess = 0;
      CK_MECHANISM dmech = { CKM_SHA256, NULL_PTR, 0 };
      rv = f->C_OpenSession(here, CKF_RW_SESSION | CKF_SERIAL_SESSION,
                            NULL_PTR, NULL_PTR, &csess);
      CHECKC(rv == CKR_OK && csess != 0, "scratch session for re-auth");
      rv = f->C_DigestInit(csess, &dmech);
      CHECKC(rv == CKR_OK, "digest init for context re-auth");
      rv = f->C_Login(csess, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR) "1234", 4);
      CHECKC(rv == CKR_OK, "context re-auth ok");
      rv = f->C_GetSessionInfo(csess, &sinfo);
      CHECKC(rv == CKR_OK && sinfo.state == CKS_RW_USER_FUNCTIONS,
             "context session shows user functions");
      rv = f->C_CloseSession(csess);
      CHECKC(rv == CKR_OK, "scratch session closed");
    }
    rv = f->C_Logout(sess);
    CHECKC(rv == CKR_OK, "logout after context ok");
    rv = f->C_Login(sess, 99, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKC(rv == CKR_USER_TYPE_INVALID, "bogus user type invalid");
    rv = f->C_Login(sess, CKU_USER, NULL_PTR, 0);
    CHECKC(rv == CKR_PIN_INCORRECT, "empty PIN incorrect");
    /* SO lockout last: three misses lock the role (user flows
     * elsewhere in this run are unaffected). */
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "bad1", 4);
    CHECKC(rv == CKR_PIN_INCORRECT, "SO miss one");
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "bad2", 4);
    CHECKC(rv == CKR_PIN_INCORRECT, "SO miss two");
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "bad3", 4);
    CHECKC(rv == CKR_PIN_LOCKED, "SO miss three locks");
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
    CHECKC(rv == CKR_PIN_LOCKED, "locked SO stays locked");
    rv = f->C_GetTokenInfo(here, &tinf);
    CHECKC(rv == CKR_OK && (tinf.flags & CKF_SO_PIN_LOCKED) != 0,
           "token shows SO locked");
  }
  /* ---- keygen is real: AES + RSA pair on a real
   * session, both topologies (public session objects: no login
   * dependence) ---- */
  {
    CK_SESSION_HANDLE ksess = 0;
    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE kt;
    CK_ULONG vlen;
    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_HANDLE key = 0, key2 = 0, pub = 0, priv = 0;
    CK_ULONG rlen;
    CK_OBJECT_CLASS rcls;
    CK_ATTRIBUTE get[1];
    CK_MECHANISM kgm;
    rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &ksess);
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &ksess);
      }
    }
    CHECKC(rv == CKR_OK && ksess != 0, "keygen session opens");
    cls = CKO_SECRET_KEY;
    kt = CKK_AES;
    vlen = 16;
    {
      CK_BYTE val1[16];
      CK_BYTE val2[16];
      CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      kgm.mechanism = CKM_AES_KEY_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKey(ksess, NULL_PTR, tmpl, 6, &key);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "GenerateKey NULL mech refused");
      rv = f->C_GenerateKey(ksess, &kgm, tmpl, 6, NULL_PTR);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "GenerateKey NULL handle refused");
      rv = f->C_GenerateKey(ksess, &kgm, tmpl, 6, &key);
      CHECKC(rv == CKR_OK && key != 0, "AES-128 keygen ok");
      get[0].type = CKA_VALUE_LEN;
      get[0].pValue = &rlen;
      get[0].ulValueLen = sizeof(rlen);
      rv = f->C_GetAttributeValue(ksess, key, get, 1);
      CHECKC(rv == CKR_OK && rlen == 16, "genned key VALUE_LEN 16");
      get[0].type = CKA_VALUE;
      get[0].pValue = val1;
      get[0].ulValueLen = sizeof(val1);
      rv = f->C_GetAttributeValue(ksess, key, get, 1);
      CHECKC(rv == CKR_OK && get[0].ulValueLen == 16, "genned key VALUE reads");
      rv = f->C_GenerateKey(ksess, &kgm, tmpl, 6, &key2);
      CHECKC(rv == CKR_OK && key2 != 0 && key2 != key, "second AES keygen ok");
      get[0].type = CKA_VALUE;
      get[0].pValue = val2;
      get[0].ulValueLen = sizeof(val2);
      rv = f->C_GetAttributeValue(ksess, key2, get, 1);
      CHECKC(rv == CKR_OK && memcmp(val1, val2, 16) != 0,
             "two keygens differ (fresh randomness)");
      key2 = 0;
      vlen = 15;
      rv = f->C_GenerateKey(ksess, &kgm, tmpl, 6, &key2);
      CHECKC(rv == CKR_TEMPLATE_INCONSISTENT, "AES-15 refused");
      CHECKC(key2 == 0, "refused keygen writes no handle");
      rv = f->C_GenerateKey(ksess, &kgm, tmpl, 2, &key2);
      CHECKC(rv == CKR_TEMPLATE_INCOMPLETE, "missing VALUE_LEN incomplete");
    }
    /* RSA pairgen is real (spec real: tested): the pair
     * lands with distinct handles, honest classes, and stamped
     * components (256-byte modulus, default exponent).
     * Out-of-window sizes refuse without writing handles. */
    {
      CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY;
      CK_OBJECT_CLASS scls = CKO_PRIVATE_KEY;
      CK_KEY_TYPE rkt = CKK_RSA;
      CK_ULONG bits = 2048;
      CK_BYTE ebuf[8];
      static CK_BYTE mod[256];
      CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pcls, sizeof(pcls) },
        { CKA_KEY_TYPE, &rkt, sizeof(rkt) },
        { CKA_MODULUS_BITS, &bits, sizeof(bits) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
      };
      CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &scls, sizeof(scls) },
        { CKA_KEY_TYPE, &rkt, sizeof(rkt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
      };
      pub = 0;
      priv = 0;
      kgm.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKeyPair(ksess, &kgm, pubT, 4, privT, 3, &pub, &priv);
      CHECKC(rv == CKR_OK && pub != 0 && priv != 0 && pub != priv,
             "RSA pair ok with distinct handles");
      get[0].type = CKA_CLASS;
      get[0].pValue = &rcls;
      get[0].ulValueLen = sizeof(rcls);
      rv = f->C_GetAttributeValue(ksess, pub, get, 1);
      CHECKC(rv == CKR_OK && rcls == CKO_PUBLIC_KEY,
             "RSA pair pub class reads");
      get[0].type = CKA_MODULUS;
      get[0].pValue = mod;
      get[0].ulValueLen = sizeof(mod);
      rv = f->C_GetAttributeValue(ksess, pub, get, 1);
      CHECKC(rv == CKR_OK && get[0].ulValueLen == 256,
             "RSA pair modulus reads 256 bytes");
      get[0].type = CKA_PUBLIC_EXPONENT;
      get[0].pValue = ebuf;
      get[0].ulValueLen = sizeof(ebuf);
      rv = f->C_GetAttributeValue(ksess, pub, get, 1);
      CHECKC(rv == CKR_OK && get[0].ulValueLen == 3 && ebuf[0] == 1 &&
                 ebuf[1] == 0 && ebuf[2] == 1,
             "RSA pair default exponent reads 65537");
      bits = 1024;
      pub = 0;
      priv = 0;
      rv = f->C_GenerateKeyPair(ksess, &kgm, pubT, 4, privT, 3, &pub, &priv);
      CHECKC(rv == CKR_TEMPLATE_INCONSISTENT, "RSA-1024 refused");
      CHECKC(pub == 0 && priv == 0, "refused pairgen writes no handles");
    }
    /* EC P-256 pairgen is real (spec real: tested): the pair
     * lands with distinct handles, honest classes, and private
     * material; the sign section below proves it signs. */
    {
      static const CK_BYTE p256oid[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
      };
      CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY;
      CK_OBJECT_CLASS scls = CKO_PRIVATE_KEY;
      CK_KEY_TYPE ekt = CKK_EC;
      CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pcls, sizeof(pcls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_EC_PARAMS, (CK_VOID_PTR) p256oid, sizeof(p256oid) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &scls, sizeof(scls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      CK_ULONG vlen2 = 0;
      pub = 0;
      priv = 0;
      kgm.mechanism = CKM_EC_KEY_PAIR_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKeyPair(ksess, NULL_PTR, pubT, 6, privT, 6,
                                &pub, &priv);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "GenerateKeyPair NULL mech refused");
      rv = f->C_GenerateKeyPair(ksess, &kgm, pubT, 6, privT, 6, &pub, &priv);
      CHECKC(rv == CKR_OK && pub != 0 && priv != 0 && pub != priv,
             "EC P-256 pair ok with distinct handles");
      get[0].type = CKA_CLASS;
      get[0].pValue = &rcls;
      get[0].ulValueLen = sizeof(rcls);
      rv = f->C_GetAttributeValue(ksess, pub, get, 1);
      CHECKC(rv == CKR_OK && rcls == CKO_PUBLIC_KEY, "EC pair pub class reads");
      rv = f->C_GetAttributeValue(ksess, priv, get, 1);
      CHECKC(rv == CKR_OK && rcls == CKO_PRIVATE_KEY,
             "EC pair priv class reads");
      get[0].type = CKA_VALUE;
      get[0].pValue = NULL_PTR;
      get[0].ulValueLen = 0;
      rv = f->C_GetAttributeValue(ksess, priv, get, 1);
      vlen2 = get[0].ulValueLen;
      CHECKC(rv == CKR_OK && vlen2 > 100 && vlen2 < 200,
             "EC pair priv carries DER material");
    }
    rv = f->C_CloseSession(ksess);
    CHECKC(rv == CKR_OK, "keygen session closes");
  }
  /* ---- sign/verify are real: ECDSA + HMAC one-shot
   * and multipart on a real session, both topologies ---- */
  {
    static const CK_BYTE p256oid[] = {
      0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_SESSION_HANDLE ssess = 0;
    CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS scls = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
    CK_KEY_TYPE ekt = CKK_EC;
    CK_KEY_TYPE gkt = CKK_GENERIC_SECRET;
    CK_ULONG vlen = 16;
    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_HANDLE pub = 0, priv = 0, hmkey = 0;
    CK_BYTE sig[128];
    CK_ULONG sigLen;
    CK_MECHANISM kgm;
    CK_MECHANISM sm;
    CK_MECHANISM hm;
    CK_MECHANISM gm;
    CK_ULONG gpar = 16;
    rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &ssess);
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &ssess);
      }
    }
    CHECKC(rv == CKR_OK && ssess != 0, "sign session opens");
    {
      CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pcls, sizeof(pcls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_EC_PARAMS, (CK_VOID_PTR) p256oid, sizeof(p256oid) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &scls, sizeof(scls) },
        { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE htmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &gkt, sizeof(gkt) },
        { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
      };
      sm.mechanism = CKM_ECDSA_SHA256;
      sm.pParameter = NULL_PTR;
      sm.ulParameterLen = 0;
      kgm.mechanism = CKM_EC_KEY_PAIR_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKeyPair(ssess, &kgm, pubT, 5, privT, 4,
                                &pub, &priv);
      CHECKC(rv == CKR_OK && pub != 0 && priv != 0, "sign EC pair mints");
      hm.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
      hm.pParameter = NULL_PTR;
      hm.ulParameterLen = 0;
      rv = f->C_GenerateKey(ssess, &hm, htmpl, 6, &hmkey);
      CHECKC(rv == CKR_OK && hmkey != 0, "sign HMAC key mints");
    }
    /* ECDSA one-shot + edges. */
    sigLen = sizeof(sig);
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "abc", 3, sig, &sigLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "sign without init is NOT_INITIALIZED");
    rv = f->C_SignInit(ssess, NULL_PTR, priv);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "SignInit NULL mech refused");
    rv = f->C_SignInit(ssess, &sm, 9999);
    CHECKC(rv == CKR_OBJECT_HANDLE_INVALID, "SignInit bad key refused");
    rv = f->C_SignInit(ssess, &sm, pub);
    CHECKC(rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "SignInit with verify-only key refused");
    rv = f->C_SignInit(ssess, &sm, priv);
    CHECKC(rv == CKR_OK, "ECDSA SignInit ok");
    rv = f->C_SignInit(ssess, &sm, priv);
    CHECKC(rv == CKR_OPERATION_ACTIVE, "second SignInit is ACTIVE");
    sigLen = 0;
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 64,
           "sign size query reports raw length");
    /* The query leaves the op live: the follow-up one-shot signs. */
    sigLen = sizeof(sig);
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "abc", 3, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 64,
           "one-shot after query yields raw bytes");
    rv = f->C_SignInit(ssess, &sm, priv);
    CHECKC(rv == CKR_OK, "re-init after one-shot");
    sigLen = 10;
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "abc", 3, sig, &sigLen);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && sigLen == 64,
           "short sign buffer reports raw length");
    sigLen = sizeof(sig);
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "abc", 3, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 64,
           "one-shot sign yields raw bytes");
    /* ECDSA verify one-shot + tamper. */
    rv = f->C_Verify(ssess, (CK_BYTE_PTR) "abc", 3, sig, sigLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "verify without init is NOT_INITIALIZED");
    rv = f->C_VerifyInit(ssess, &sm, priv);
    CHECKC(rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "VerifyInit with sign-only key refused");
    rv = f->C_VerifyInit(ssess, &sm, pub);
    CHECKC(rv == CKR_OK, "ECDSA VerifyInit ok");
    rv = f->C_Verify(ssess, (CK_BYTE_PTR) "abc", 3, sig, sigLen);
    CHECKC(rv == CKR_OK, "ECDSA verify ok");
    rv = f->C_VerifyInit(ssess, &sm, pub);
    CHECKC(rv == CKR_OK, "re-init for tamper");
    sig[((size_t) sigLen) - 1] ^= 0xFF;
    rv = f->C_Verify(ssess, (CK_BYTE_PTR) "abc", 3, sig, sigLen);
    CHECKC(rv == CKR_SIGNATURE_INVALID, "tampered ECDSA refused");
    /* Explicit DER encoding stays available on request (direct:
     * our vendor params convention). Proxied, the shim refuses
     * params on parameterless CKM_ECDSA_SHA256 before forwarding
     * (validate_mechanism/check_operation), so the init surfaces
     * PARAM_INVALID and no op starts. */
    {
      CK_MECHANISM dsm;
      CK_BYTE derp[] = { 'D', 'E', 'R' };
      dsm.mechanism = CKM_ECDSA_SHA256;
      dsm.pParameter = derp;
      dsm.ulParameterLen = sizeof(derp);
      rv = f->C_SignInit(ssess, &dsm, priv);
      if (!isProxy) {
        CHECKC(rv == CKR_OK, "DER SignInit ok");
        sigLen = sizeof(sig);
        rv = f->C_Sign(ssess, (CK_BYTE_PTR) "abc", 3, sig, &sigLen);
        CHECKC(rv == CKR_OK && sigLen > 64 && sigLen <= 72 && sig[0] == 0x30,
               "explicit DER yields DER bytes");
      } else {
        CHECKC(rv == CKR_MECHANISM_PARAM_INVALID,
               "proxied DER params are PARAM_INVALID");
      }
    }
    /* ECDSA multipart. */
    rv = f->C_SignUpdate(ssess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "sign update without init refused");
    rv = f->C_SignFinal(ssess, sig, &sigLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "sign final without init refused");
    rv = f->C_SignInit(ssess, &sm, priv);
    CHECKC(rv == CKR_OK, "multipart sign init ok");
    rv = f->C_SignUpdate(ssess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OK, "multipart sign update one ok");
    rv = f->C_SignUpdate(ssess, (CK_BYTE_PTR) "bc", 2);
    CHECKC(rv == CKR_OK, "multipart sign update two ok");
    sigLen = sizeof(sig);
    rv = f->C_SignFinal(ssess, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 64,
           "multipart sign final yields raw");
    /* Final size query preserves the staged signature. */
    rv = f->C_SignInit(ssess, &sm, priv);
    CHECKC(rv == CKR_OK, "sign init for final-query");
    rv = f->C_SignUpdate(ssess, (CK_BYTE_PTR) "abc", 3);
    CHECKC(rv == CKR_OK, "sign update for final-query");
    sigLen = 0;
    rv = f->C_SignFinal(ssess, NULL_PTR, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 64,
           "sign final query reports raw length");
    sigLen = sizeof(sig);
    rv = f->C_SignFinal(ssess, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 64,
           "sign final after query yields raw bytes");
    rv = f->C_VerifyUpdate(ssess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "verify update without init refused");
    rv = f->C_VerifyInit(ssess, &sm, pub);
    CHECKC(rv == CKR_OK, "multipart verify init ok");
    rv = f->C_VerifyUpdate(ssess, (CK_BYTE_PTR) "a", 1);
    CHECKC(rv == CKR_OK, "multipart verify update one ok");
    rv = f->C_VerifyUpdate(ssess, (CK_BYTE_PTR) "bc", 2);
    CHECKC(rv == CKR_OK, "multipart verify update two ok");
    rv = f->C_VerifyFinal(ssess, sig, sigLen);
    CHECKC(rv == CKR_OK, "multipart verify final ok");
    /* HMAC one-shot + GENERAL truncation. */
    hm.mechanism = CKM_SHA256_HMAC;
    hm.pParameter = NULL_PTR;
    hm.ulParameterLen = 0;
    rv = f->C_SignInit(ssess, &hm, hmkey);
    CHECKC(rv == CKR_OK, "HMAC SignInit ok");
    sigLen = sizeof(sig);
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "Hi There", 8, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 32, "HMAC sign yields 32 bytes");
    rv = f->C_VerifyInit(ssess, &hm, hmkey);
    CHECKC(rv == CKR_OK, "HMAC VerifyInit ok");
    rv = f->C_Verify(ssess, (CK_BYTE_PTR) "Hi There", 8, sig, sigLen);
    CHECKC(rv == CKR_OK, "HMAC verify ok");
    /* Key-type matrix: wrong-typed keys refuse INCONSISTENT. */
    {
      CK_KEY_TYPE aakt = CKK_AES;
      CK_ULONG avlen = 16;
      CK_ATTRIBUTE atmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &aakt, sizeof(aakt) },
        { CKA_VALUE_LEN, &avlen, sizeof(avlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM agm, cm;
      CK_BYTE iv[16] = { 0 };
      CK_OBJECT_HANDLE aeskey = 0;
      agm.mechanism = CKM_AES_KEY_GEN;
      agm.pParameter = NULL_PTR;
      agm.ulParameterLen = 0;
      rv = f->C_GenerateKey(ssess, &agm, atmpl, 6, &aeskey);
      CHECKC(rv == CKR_OK && aeskey != 0, "matrix AES key mints");
      rv = f->C_SignInit(ssess, &hm, aeskey);
      CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
             "HMAC SignInit with AES key refused");
      cm.mechanism = CKM_AES_CBC;
      cm.pParameter = iv;
      cm.ulParameterLen = sizeof(iv);
      rv = f->C_EncryptInit(ssess, &cm, hmkey);
      CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
             "AES-CBC EncryptInit with generic key refused");
    }
    /* Per-digest HMAC key types serve their own mechanism only. */
    {
      CK_KEY_TYPE h256kt = CKK_SHA256_HMAC, h512kt = CKK_SHA512_HMAC;
      CK_BYTE hval[32] = { 0 };
      CK_OBJECT_HANDLE h256 = 0, h512 = 0;
      CK_ATTRIBUTE ht[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &h256kt, sizeof(h256kt) },
        { CKA_VALUE, hval, sizeof(hval) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }
      };
      rv = f->C_CreateObject(ssess, ht, 5, &h256);
      CHECKC(rv == CKR_OK && h256 != 0, "SHA256-HMAC key imports");
      ht[1].pValue = &h512kt;
      rv = f->C_CreateObject(ssess, ht, 5, &h512);
      CHECKC(rv == CKR_OK && h512 != 0, "SHA512-HMAC key imports");
      rv = f->C_SignInit(ssess, &hm, h256);
      CHECKC(rv == CKR_OK, "HMAC SignInit with matching HMAC key ok");
      sigLen = sizeof(sig);
      rv = f->C_Sign(ssess, (CK_BYTE_PTR) "x", 1, sig, &sigLen);
      CHECKC(rv == CKR_OK && sigLen == 32, "matching HMAC key signs");
      rv = f->C_SignInit(ssess, &hm, h512);
      CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
             "HMAC SignInit with mismatched HMAC key refused");
    }
    /* HOTP matrix row: CKK_HOTP keys only; RFC 4226 vector 0. */
    {
      CK_KEY_TYPE hotpkt = CKK_HOTP;
      CK_BYTE hotpval[20] = { '1','2','3','4','5','6','7','8','9','0',
                                 '1','2','3','4','5','6','7','8','9','0' };
      CK_OBJECT_HANDLE hotpk = 0;
      CK_ATTRIBUTE hott[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &hotpkt, sizeof(hotpkt) },
        { CKA_VALUE, hotpval, sizeof(hotpval) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM hotpm;
      CK_BYTE hotpp[16] = { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,6 };
      rv = f->C_CreateObject(ssess, hott, 6, &hotpk);
      CHECKC(rv == CKR_OK && hotpk != 0, "HOTP key imports");
      hotpm.mechanism = CKM_HOTP;
      hotpm.pParameter = hotpp;
      hotpm.ulParameterLen = sizeof(hotpp);
      if (!isProxy) {
        rv = f->C_SignInit(ssess, &hotpm, hmkey);
        CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
               "HOTP SignInit with generic key refused");
        rv = f->C_SignInit(ssess, &hotpm, hotpk);
        CHECKC(rv == CKR_OK, "HOTP SignInit with HOTP key ok");
        sigLen = sizeof(sig);
        rv = f->C_Sign(ssess, (CK_BYTE_PTR) "", 0, sig, &sigLen);
        CHECKC(rv == CKR_OK && sigLen == 6 && memcmp(sig, "755224", 6) == 0,
               "HOTP counter 0 yields 755224");
        rv = f->C_VerifyInit(ssess, &hotpm, hotpk);
        CHECKC(rv == CKR_OK, "HOTP VerifyInit with HOTP key ok");
        rv = f->C_Verify(ssess, (CK_BYTE_PTR) "", 0, sig, sigLen);
        CHECKC(rv == CKR_OK, "HOTP verify of its own digits ok");
      } else {
        /* The shim's check_operation rejects parameterized
         * invocations for mechanisms absent from its shape
         * registry (0x291 unmapped in
         * mechanism_params_default.toml) with PARAM_INVALID
         * before forwarding — the ECDSA-DER precedent. */
        rv = f->C_SignInit(ssess, &hotpm, hmkey);
        CHECKC(rv == CKR_MECHANISM_PARAM_INVALID,
               "proxied HOTP params are PARAM_INVALID");
      }
    }
    gm.mechanism = CKM_SHA256_HMAC_GENERAL;
    gm.pParameter = &gpar;
    gm.ulParameterLen = sizeof(gpar);
    rv = f->C_SignInit(ssess, &gm, hmkey);
    CHECKC(rv == CKR_OK, "HMAC-GENERAL SignInit ok");
    sigLen = sizeof(sig);
    rv = f->C_Sign(ssess, (CK_BYTE_PTR) "Hi There", 8, sig, &sigLen);
    CHECKC(rv == CKR_OK && sigLen == 16, "HMAC-GENERAL sign yields 16 bytes");
    rv = f->C_VerifyInit(ssess, &gm, hmkey);
    CHECKC(rv == CKR_OK, "HMAC-GENERAL VerifyInit ok");
    rv = f->C_Verify(ssess, (CK_BYTE_PTR) "Hi There", 8, sig, sigLen);
    CHECKC(rv == CKR_OK, "HMAC-GENERAL verify ok");
    gm.ulParameterLen = 0;
    rv = f->C_SignInit(ssess, &gm, hmkey);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "HMAC-GENERAL empty params refused");
    rv = f->C_CloseSession(ssess);
    CHECKC(rv == CKR_OK, "sign session closes");
  }
  /* ---- encrypt/decrypt are real: AES-CBC-PAD and
   * AES-CBC one-shot and multipart on a real session, both
   * topologies ---- */
  {
    CK_SESSION_HANDLE esess = 0;
    CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
    CK_KEY_TYPE akt = CKK_AES;
    CK_ULONG vlen = 32;
    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_HANDLE ekey = 0;
    CK_BYTE iv[16];
    CK_BYTE ct[64];
    CK_BYTE pt[64];
    CK_ULONG ctLen;
    CK_ULONG ptLen;
    CK_ULONG partLen = 0;
    CK_MECHANISM em;
    CK_MECHANISM dm;
    CK_MECHANISM cm;
    memset(iv, 0xA5, sizeof(iv));
    rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &esess);
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &esess);
      }
    }
    CHECKC(rv == CKR_OK && esess != 0, "crypt session opens");
    {
      CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM kgm;
      kgm.mechanism = CKM_AES_KEY_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKey(esess, &kgm, tmpl, 6, &ekey);
      CHECKC(rv == CKR_OK && ekey != 0, "crypt AES-256 key mints");
    }
    em.mechanism = CKM_AES_CBC_PAD;
    em.pParameter = iv;
    em.ulParameterLen = sizeof(iv);
    dm.mechanism = CKM_AES_CBC_PAD;
    dm.pParameter = iv;
    dm.ulParameterLen = sizeof(iv);
    /* Encrypt one-shot + edges. */
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "abc", 3, ct, &ctLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "encrypt without init is NOT_INITIALIZED");
    rv = f->C_EncryptInit(esess, NULL_PTR, ekey);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "EncryptInit NULL mech refused");
    {
      CK_MECHANISM noiv;
      noiv.mechanism = CKM_AES_CBC_PAD;
      noiv.pParameter = NULL_PTR;
      noiv.ulParameterLen = 0;
      rv = f->C_EncryptInit(esess, &noiv, ekey);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "EncryptInit empty IV refused");
    }
    rv = f->C_EncryptInit(esess, &em, 9999);
    CHECKC(rv == CKR_OBJECT_HANDLE_INVALID, "EncryptInit bad key refused");
    rv = f->C_EncryptInit(esess, &em, ekey);
    CHECKC(rv == CKR_OK, "CBC-PAD EncryptInit ok");
    rv = f->C_EncryptInit(esess, &em, ekey);
    CHECKC(rv == CKR_OPERATION_ACTIVE, "second EncryptInit is ACTIVE");
    ctLen = 0;
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "abc", 3, NULL_PTR, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "encrypt size query reports 16");
    /* The query leaves the op live: the follow-up one-shot encrypts. */
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "abc", 3, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "one-shot after query yields 16 bytes");
    rv = f->C_EncryptInit(esess, &em, ekey);
    CHECKC(rv == CKR_OK, "re-init after one-shot");
    ctLen = 8;
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "abc", 3, ct, &ctLen);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && ctLen == 16,
           "short encrypt buffer reports 16");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "abc", 3, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "one-shot encrypt yields 16 bytes");
    /* Decrypt one-shot + tamper. */
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "decrypt without init is NOT_INITIALIZED");
    rv = f->C_DecryptInit(esess, &dm, ekey);
    CHECKC(rv == CKR_OK, "CBC-PAD DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 3 && memcmp(pt, "abc", 3) == 0,
           "one-shot decrypt recovers abc");
    /* Decrypt size query preserves the staged plaintext. */
    rv = f->C_DecryptInit(esess, &dm, ekey);
    CHECKC(rv == CKR_OK, "re-init for decrypt query");
    ptLen = 0;
    rv = f->C_Decrypt(esess, ct, ctLen, NULL_PTR, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 3, "decrypt size query reports 3");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 3 && memcmp(pt, "abc", 3) == 0,
           "one-shot after query recovers abc");
    rv = f->C_DecryptInit(esess, &dm, ekey);
    CHECKC(rv == CKR_OK, "re-init for tamper");
    ct[ctLen - 1] ^= 0xFF;
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "tampered ciphertext refused");
    ct[ctLen - 1] ^= 0xFF;
    /* AES-XTS: import a 32-byte CKK_AES_XTS key, one-shot a 21-byte
     * data unit under the 16-byte tweak, roundtrip; short units
     * refused at the planner floor. */
    {
      CK_OBJECT_CLASS xtcls = CKO_SECRET_KEY;
      CK_KEY_TYPE xtkt = CKK_AES_XTS;
      CK_BYTE xtval[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
      };
      CK_ATTRIBUTE xttmpl[] = {
        { CKA_CLASS, &xtcls, sizeof(xtcls) },
        { CKA_KEY_TYPE, &xtkt, sizeof(xtkt) },
        { CKA_VALUE, xtval, sizeof(xtval) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_OBJECT_HANDLE xtkey = 0;
      CK_BYTE tweak[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
      };
      CK_MECHANISM xtm;
      CK_BYTE xtct[64], xtpt[64];
      CK_ULONG xtctLen, xtptLen;
      rv = f->C_CreateObject(esess, xttmpl, 6, &xtkey);
      CHECKC(rv == CKR_OK && xtkey != 0, "xts key imports");
      xtm.mechanism = CKM_AES_XTS;
      xtm.pParameter = tweak;
      xtm.ulParameterLen = sizeof(tweak);
      rv = f->C_EncryptInit(esess, &xtm, xtkey);
      CHECKC(rv == CKR_OK, "xts EncryptInit ok");
      xtctLen = sizeof(xtct);
      rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "twenty-one byte unit!", 21, xtct, &xtctLen);
      CHECKC(rv == CKR_OK && xtctLen == 21, "xts one-shot yields 21 bytes");
      rv = f->C_DecryptInit(esess, &xtm, xtkey);
      CHECKC(rv == CKR_OK, "xts DecryptInit ok");
      xtptLen = sizeof(xtpt);
      rv = f->C_Decrypt(esess, xtct, xtctLen, xtpt, &xtptLen);
      CHECKC(rv == CKR_OK && xtptLen == 21
             && memcmp(xtpt, "twenty-one byte unit!", 21) == 0,
             "xts decrypt recovers");
      rv = f->C_EncryptInit(esess, &xtm, xtkey);
      CHECKC(rv == CKR_OK, "xts re-init for short");
      xtctLen = sizeof(xtct);
      rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "short", 5, xtct, &xtctLen);
      CHECKC(rv == CKR_DATA_LEN_RANGE, "xts short unit refused");
    }
    /* Multipart (sub-block updates buffer; final emits). */
    rv = f->C_EncryptUpdate(esess, (CK_BYTE_PTR) "a", 1, ct, &partLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "encrypt update without init refused");
    rv = f->C_EncryptFinal(esess, ct, &ctLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "encrypt final without init refused");
    rv = f->C_EncryptInit(esess, &em, ekey);
    CHECKC(rv == CKR_OK, "multipart encrypt init ok");
    partLen = sizeof(ct);
    rv = f->C_EncryptUpdate(esess, (CK_BYTE_PTR) "a", 1, ct, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "encrypt update buffers");
    partLen = sizeof(ct);
    rv = f->C_EncryptUpdate(esess, (CK_BYTE_PTR) "bc", 2, ct, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "encrypt update two buffers");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "d", 1, ct, &ctLen);
    CHECKC(rv == CKR_OPERATION_ACTIVE, "one-shot over buffered is ACTIVE");
    /* The refused one-shot terminates the op (spec: every error
     * other than BUFFER_TOO_SMALL terminates); a re-init follows. */
    ctLen = sizeof(ct);
    rv = f->C_EncryptFinal(esess, ct, &ctLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "final after refused one-shot is NOT_INITIALIZED");
    rv = f->C_EncryptInit(esess, &em, ekey);
    CHECKC(rv == CKR_OK, "re-init after termination ok");
    partLen = sizeof(ct);
    rv = f->C_EncryptUpdate(esess, (CK_BYTE_PTR) "abc", 3, ct, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "update after re-init buffers");
    ctLen = sizeof(ct);
    rv = f->C_EncryptFinal(esess, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "encrypt final yields 16 bytes");
    /* Encrypt-final size query preserves the staged block. */
    rv = f->C_EncryptInit(esess, &em, ekey);
    CHECKC(rv == CKR_OK, "encrypt init for final-query");
    partLen = sizeof(ct);
    rv = f->C_EncryptUpdate(esess, (CK_BYTE_PTR) "abc", 3, ct, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "encrypt update for final-query buffers");
    ctLen = 0;
    rv = f->C_EncryptFinal(esess, NULL_PTR, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "encrypt final query reports 16");
    ctLen = sizeof(ct);
    rv = f->C_EncryptFinal(esess, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "encrypt final after query yields 16 bytes");
    rv = f->C_DecryptUpdate(esess, ct, 8, pt, &partLen);
    CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
           "decrypt update without init refused");
    rv = f->C_DecryptInit(esess, &dm, ekey);
    CHECKC(rv == CKR_OK, "multipart decrypt init ok");
    partLen = sizeof(pt);
    rv = f->C_DecryptUpdate(esess, ct, 8, pt, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "decrypt update buffers");
    partLen = sizeof(pt);
    rv = f->C_DecryptUpdate(esess, ct + 8, 8, pt, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "decrypt update two buffers");
    ptLen = sizeof(pt);
    rv = f->C_DecryptFinal(esess, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 3 && memcmp(pt, "abc", 3) == 0,
           "decrypt final recovers abc");
    /* Decrypt-final size query preserves the staged plaintext. */
    rv = f->C_DecryptInit(esess, &dm, ekey);
    CHECKC(rv == CKR_OK, "decrypt init for final-query");
    partLen = sizeof(pt);
    rv = f->C_DecryptUpdate(esess, ct, 8, pt, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "decrypt update for final-query buffers");
    partLen = sizeof(pt);
    rv = f->C_DecryptUpdate(esess, ct + 8, 8, pt, &partLen);
    CHECKC(rv == CKR_OK && partLen == 0, "decrypt update two for final-query buffers");
    ptLen = 0;
    rv = f->C_DecryptFinal(esess, NULL_PTR, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 3, "decrypt final query reports 3");
    ptLen = sizeof(pt);
    rv = f->C_DecryptFinal(esess, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 3 && memcmp(pt, "abc", 3) == 0,
           "decrypt final after query recovers abc");
    /* Streaming updates: releasable blocks emit, the suffix retains,
     * queries and short buffers consume nothing. */
    {
      CK_BYTE longPt[48];
      CK_BYTE streamCt[64];
      CK_BYTE streamPt[64];
      CK_ULONG streamLen;
      CK_ULONG finalLen;
      memset(longPt, 0x41, sizeof(longPt));
      rv = f->C_EncryptInit(esess, &em, ekey);
      CHECKC(rv == CKR_OK, "stream encrypt init ok");
      streamLen = 0;
      rv = f->C_EncryptUpdate(esess, longPt, 17, NULL_PTR, &streamLen);
      CHECKC(rv == CKR_OK && streamLen == 16, "update query reports 16");
      streamLen = sizeof(streamCt);
      rv = f->C_EncryptUpdate(esess, longPt, 17, streamCt, &streamLen);
      CHECKC(rv == CKR_OK && streamLen == 16,
             "update streams 16 (query consumed nothing)");
      streamLen = 1;
      rv = f->C_EncryptUpdate(esess, longPt + 17, 31, streamCt + 16, &streamLen);
      CHECKC(rv == CKR_BUFFER_TOO_SMALL && streamLen == 16,
             "short update refuses with the streamable length");
      streamLen = sizeof(streamCt) - 16;
      rv = f->C_EncryptUpdate(esess, longPt + 17, 31, streamCt + 16, &streamLen);
      CHECKC(rv == CKR_OK && streamLen == 16,
             "retry after short streams 16 (consumed nothing)");
      finalLen = sizeof(streamCt) - 32;
      rv = f->C_EncryptFinal(esess, streamCt + 32, &finalLen);
      CHECKC(rv == CKR_OK && finalLen == 32, "stream final yields 32");
      rv = f->C_DecryptInit(esess, &dm, ekey);
      CHECKC(rv == CKR_OK, "stream decrypt init ok");
      ptLen = sizeof(streamPt);
      rv = f->C_Decrypt(esess, streamCt, 64, streamPt, &ptLen);
      CHECKC(rv == CKR_OK && ptLen == 48 && memcmp(streamPt, longPt, 48) == 0,
             "streamed ciphertext decrypts to 48 bytes");
      /* ECB drains fully yet stays multipart-started. */
      {
        CK_MECHANISM ecbm;
        ecbm.mechanism = CKM_AES_ECB;
        ecbm.pParameter = NULL_PTR;
        ecbm.ulParameterLen = 0;
        rv = f->C_EncryptInit(esess, &ecbm, ekey);
        CHECKC(rv == CKR_OK, "ECB init ok");
        streamLen = sizeof(streamCt);
        rv = f->C_EncryptUpdate(esess, (CK_BYTE_PTR) "0123456789ABCDEF", 16,
                                streamCt, &streamLen);
        CHECKC(rv == CKR_OK && streamLen == 16, "ECB update streams 16");
        ctLen = sizeof(ct);
        rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "x", 1, ct, &ctLen);
        CHECKC(rv == CKR_OPERATION_ACTIVE, "one-shot after drained update");
      }
    }
    /* Unpadded CBC: aligned round-trips, ragged refused. */
    cm.mechanism = CKM_AES_CBC;
    cm.pParameter = iv;
    cm.ulParameterLen = sizeof(iv);
    rv = f->C_EncryptInit(esess, &cm, ekey);
    CHECKC(rv == CKR_OK, "CBC EncryptInit ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "0123456789ABCDEF", 16, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "CBC encrypt yields 16 bytes");
    rv = f->C_DecryptInit(esess, &cm, ekey);
    CHECKC(rv == CKR_OK, "CBC DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 16 &&
               memcmp(pt, "0123456789ABCDEF", 16) == 0,
           "CBC decrypt recovers 16 bytes");
    /* AES-GCM: tag-appended round-trip; tamper, short input, and the
     * provider-generated-IV shape fail closed. */
    {
      CK_BYTE giv[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
      CK_BYTE gaad[2] = { 'A', 'D' };
      CK_AES_GCM_PARAMS gp;
      CK_MECHANISM gm;
      gp.pIv = giv;
      gp.ulIvLen = sizeof(giv);
      gp.ulIvBits = sizeof(giv) * 8;
      gp.pAAD = gaad;
      gp.ulAADLen = sizeof(gaad);
      gp.ulTagBits = 128;
      gm.mechanism = CKM_AES_GCM;
      gm.pParameter = &gp;
      gm.ulParameterLen = sizeof(gp);
      rv = f->C_EncryptInit(esess, &gm, ekey);
      CHECKC(rv == CKR_OK, "GCM EncryptInit ok");
      ctLen = sizeof(ct);
      rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "hello!", 6, ct, &ctLen);
      CHECKC(rv == CKR_OK && ctLen == 22, "GCM encrypt appends 16-byte tag");
      rv = f->C_DecryptInit(esess, &gm, ekey);
      CHECKC(rv == CKR_OK, "GCM DecryptInit ok");
      ptLen = sizeof(pt);
      rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
      CHECKC(rv == CKR_OK && ptLen == 6 && memcmp(pt, "hello!", 6) == 0,
             "GCM decrypt recovers hello!");
      ct[ctLen - 1] ^= 0x01;
      rv = f->C_DecryptInit(esess, &gm, ekey);
      CHECKC(rv == CKR_OK, "GCM DecryptInit for tamper ok");
      ptLen = sizeof(pt);
      rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
      CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "GCM tamper fails closed");
      ct[ctLen - 1] ^= 0x01;
      rv = f->C_DecryptInit(esess, &gm, ekey);
      CHECKC(rv == CKR_OK, "GCM DecryptInit for short ok");
      ptLen = sizeof(pt);
      rv = f->C_Decrypt(esess, ct, 4, pt, &ptLen);
      CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "GCM short input fails closed");
      gp.ulIvLen = 0;
      gp.ulIvBits = 96;
      rv = f->C_EncryptInit(esess, &gm, ekey);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "GCM generated-IV refused");
    }
    /* Non-AES block ciphers route identically: an imported ARIA-256
     * key (typed CKK_ARIA, verbatim value) drives ARIA-256-CBC while
     * the AES key object is refused by the key-type matrix. Runs
     * before the ragged check: a length-range denial keeps the
     * slot (later updates can repair it), so ragged goes last. */
    {
      CK_OBJECT_CLASS acls = CKO_SECRET_KEY;
      CK_KEY_TYPE arkt = CKK_ARIA;
      CK_BBOOL aFalse = CK_FALSE, aTrue = CK_TRUE;
      CK_BYTE akey[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
      };
      CK_ATTRIBUTE itmpl[] = {
        { CKA_CLASS, &acls, sizeof(acls) },
        { CKA_KEY_TYPE, &arkt, sizeof(arkt) },
        { CKA_VALUE, akey, sizeof(akey) },
        { CKA_TOKEN, &aFalse, sizeof(aFalse) },
        { CKA_ENCRYPT, &aTrue, sizeof(aTrue) },
        { CKA_DECRYPT, &aTrue, sizeof(aTrue) }
      };
      CK_OBJECT_HANDLE ario = 0;
      CK_MECHANISM am;
      am.mechanism = CKM_ARIA_CBC;
      am.pParameter = iv;
      am.ulParameterLen = sizeof(iv);
      rv = f->C_CreateObject(esess, itmpl, 6, &ario);
      CHECKC(rv == CKR_OK && ario != 0, "ARIA key imports");
      rv = f->C_EncryptInit(esess, &am, ekey);
      CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
             "ARIA-CBC EncryptInit with AES key refused");
      rv = f->C_EncryptInit(esess, &am, ario);
      CHECKC(rv == CKR_OK, "ARIA-CBC EncryptInit ok");
      ctLen = sizeof(ct);
      rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "0123456789ABCDEF", 16, ct,
                        &ctLen);
      CHECKC(rv == CKR_OK && ctLen == 16, "ARIA-CBC encrypt yields 16 bytes");
      rv = f->C_DecryptInit(esess, &am, ario);
      CHECKC(rv == CKR_OK, "ARIA-CBC DecryptInit ok");
      ptLen = sizeof(pt);
      rv = f->C_Decrypt(esess, ct, ctLen, pt, &ptLen);
      CHECKC(rv == CKR_OK && ptLen == 16 &&
                 memcmp(pt, "0123456789ABCDEF", 16) == 0,
             "ARIA-CBC decrypt recovers 16 bytes");
    }
    rv = f->C_EncryptInit(esess, &cm, ekey);
    CHECKC(rv == CKR_OK, "re-init for ragged");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(esess, (CK_BYTE_PTR) "abc", 3, ct, &ctLen);
    CHECKC(rv == CKR_DATA_LEN_RANGE, "ragged CBC encrypt refused");
    rv = f->C_CloseSession(esess);
    CHECKC(rv == CKR_OK, "crypt session closes");
  }
  /* ---- random is real: GenerateRandom yields
   * fresh bytes; SeedRandom mixes caller seed into the DRBG ---- */
  {
    CK_SESSION_HANDLE rsess = 0;
    CK_BYTE r1[32];
    CK_BYTE r2[32];
    CK_BYTE seed[16];
    rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &rsess);
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &rsess);
      }
    }
    CHECKC(rv == CKR_OK && rsess != 0, "random session opens");
    rv = f->C_GenerateRandom(rsess, NULL_PTR, 32);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "GenerateRandom NULL buffer refused");
    rv = f->C_GenerateRandom(9999, r1, 32);
    CHECKC(rv == CKR_SESSION_HANDLE_INVALID,
           "GenerateRandom bad session refused");
    rv = f->C_GenerateRandom(rsess, r1, 0);
    CHECKC(rv == CKR_OK, "GenerateRandom zero length ok");
    rv = f->C_GenerateRandom(rsess, r1, 32);
    CHECKC(rv == CKR_OK, "GenerateRandom 32 ok");
    rv = f->C_GenerateRandom(rsess, r2, 32);
    CHECKC(rv == CKR_OK && memcmp(r1, r2, 32) != 0, "two randoms differ");
    memset(seed, 0xA5, sizeof(seed));
    rv = f->C_SeedRandom(rsess, seed, sizeof(seed));
    CHECKC(rv == CKR_OK, "SeedRandom 16 ok");
    rv = f->C_GenerateRandom(rsess, r1, 32);
    CHECKC(rv == CKR_OK, "GenerateRandom 32 ok after seed");
    rv = f->C_GenerateRandom(rsess, r2, 32);
    CHECKC(rv == CKR_OK && memcmp(r1, r2, 32) != 0,
           "randoms differ after seed");
    rv = f->C_SeedRandom(rsess, NULL_PTR, 32);
    if (!isProxy) {
      CHECKC(rv == CKR_ARGUMENTS_BAD, "SeedRandom NULL seed refused");
    } else {
      /* Proxy shim normalizes NULL input bytes to empty
       * (read_input_slice maps NULL of any length to &[]), so the
       * daemon serves a vacuous OK; direct mode refuses per the
       * pinned bad-session-first/ARGS_BAD contract. */
      CHECKC(rv == CKR_OK, "SeedRandom NULL seed vacuous via proxy");
    }
    rv = f->C_SeedRandom(9999, seed, sizeof(seed));
    CHECKC(rv == CKR_SESSION_HANDLE_INVALID,
           "SeedRandom bad session refused");
    rv = f->C_SeedRandom(rsess, seed, 0);
    CHECKC(rv == CKR_OK, "SeedRandom zero length ok");
    rv = f->C_SeedRandom(rsess, NULL_PTR, 0);
    CHECKC(rv == CKR_OK, "SeedRandom NULL zero length ok");
    /* Oversize lengths refuse before any allocation (the oracle's
     * 4 GiB probe OOM-killed the process pre-bound). 2 MiB real
     * buffers keep the pins safe in every revision. */
    {
      static const CK_ULONG big = 2 * 1024 * 1024;
      CK_BYTE_PTR gbuf = (CK_BYTE_PTR) malloc(big);
      CK_BYTE_PTR sbuf = (CK_BYTE_PTR) malloc(big);
      CHECKC(gbuf != NULL_PTR && sbuf != NULL_PTR, "oversize buffers allocate");
      if (gbuf != NULL_PTR && sbuf != NULL_PTR) {
        memset(sbuf, 0x5A, big);
        rv = f->C_GenerateRandom(rsess, gbuf, big);
        CHECKC(rv == CKR_DATA_LEN_RANGE,
               "GenerateRandom oversize refused before alloc");
        rv = f->C_SeedRandom(rsess, sbuf, big);
        CHECKC(rv == CKR_ARGUMENTS_BAD,
               "SeedRandom oversize refused before copy");
      }
      free(gbuf);
      free(sbuf);
    }
    rv = f->C_CloseSession(rsess);
    CHECKC(rv == CKR_OK, "random session closes");
  }
  /* ---- wrap/unwrap/derive are real: AES-CBC wrap
   * round-trip plus an HKDF-subset derive; non-HKDF derive
   * stays honestly unsupported ---- */
  {
    CK_SESSION_HANDLE wsess = 0;
    CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
    CK_KEY_TYPE akt = CKK_AES;
    CK_KEY_TYPE gkt = CKK_GENERIC_SECRET;
    CK_ULONG vlen = 32;
    CK_ULONG tlen = 16;
    CK_ULONG dlen = 32;
    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_HANDLE wrapKey = 0, targetKey = 0, sealedKey = 0;
    CK_OBJECT_HANDLE unwrapped = 0, derived = 0, derived2 = 0;
    CK_BYTE iv[16];
    CK_BYTE blob[64];
    CK_BYTE probe[64];
    CK_ULONG blobLen;
    CK_ULONG probeLen;
    CK_MECHANISM wm;
    CK_MECHANISM um;
    CK_MECHANISM dmpad;
    CK_MECHANISM dhkdf;
    CK_MECHANISM decdh;
    CK_HKDF_PARAMS hkdf;
    CK_BYTE infoA[] = { 'c', 't', 'x', 'A' };
    CK_BYTE infoB[] = { 'c', 't', 'x', 'B' };
    memset(iv, 0x1B, sizeof(iv));
    rv = f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                          NULL_PTR, &wsess);
    if (rv == CKR_SLOT_ID_INVALID) {
      CK_SLOT_ID psl[8];
      CK_ULONG pn = 8;
      if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
        rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &wsess);
      }
    }
    CHECKC(rv == CKR_OK && wsess != 0, "wrap session opens");
    {
      CK_ATTRIBUTE wtmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_WRAP, &bTrue, sizeof(bTrue) },
        { CKA_UNWRAP, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE ttmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_VALUE_LEN, &tlen, sizeof(tlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE stmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_VALUE_LEN, &tlen, sizeof(tlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM kgm;
      kgm.mechanism = CKM_AES_KEY_GEN;
      kgm.pParameter = NULL_PTR;
      kgm.ulParameterLen = 0;
      rv = f->C_GenerateKey(wsess, &kgm, wtmpl, 6, &wrapKey);
      CHECKC(rv == CKR_OK && wrapKey != 0, "wrapping key mints");
      rv = f->C_GenerateKey(wsess, &kgm, ttmpl, 7, &targetKey);
      CHECKC(rv == CKR_OK && targetKey != 0, "wrap target mints");
      rv = f->C_GenerateKey(wsess, &kgm, stmpl, 6, &sealedKey);
      CHECKC(rv == CKR_OK && sealedKey != 0, "derive base mints");
    }
    wm.mechanism = CKM_AES_CBC;
    wm.pParameter = iv;
    wm.ulParameterLen = sizeof(iv);
    um.mechanism = CKM_AES_CBC;
    um.pParameter = iv;
    um.ulParameterLen = sizeof(iv);
    /* Wrap dialogue: query, short, full. */
    rv = f->C_WrapKey(wsess, NULL_PTR, wrapKey, targetKey, blob, &blobLen);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "WrapKey NULL mech refused");
    dmpad.mechanism = CKM_AES_CBC_PAD;
    dmpad.pParameter = iv;
    dmpad.ulParameterLen = sizeof(iv);
    blobLen = sizeof(blob);
    rv = f->C_WrapKey(wsess, &dmpad, wrapKey, targetKey, blob, &blobLen);
    CHECKC(rv == CKR_MECHANISM_INVALID, "WrapKey PAD mech refused");
    blobLen = 0;
    rv = f->C_WrapKey(wsess, &wm, wrapKey, targetKey, NULL_PTR, &blobLen);
    CHECKC(rv == CKR_OK && blobLen == 32, "wrap size query reports 32");
    blobLen = 16;
    rv = f->C_WrapKey(wsess, &wm, wrapKey, targetKey, blob, &blobLen);
    CHECKC(rv == CKR_BUFFER_TOO_SMALL && blobLen == 32,
           "short wrap buffer reports 32");
    blobLen = sizeof(blob);
    rv = f->C_WrapKey(wsess, &wm, wrapKey, targetKey, blob, &blobLen);
    CHECKC(rv == CKR_OK && blobLen == 32, "wrap yields 32 bytes");
    probeLen = sizeof(probe);
    rv = f->C_WrapKey(wsess, &wm, targetKey, sealedKey, probe, &probeLen);
    CHECKC(rv == CKR_KEY_FUNCTION_NOT_PERMITTED,
           "wrap without WRAP mark refused");
    /* Wrap/unwrap with a non-AES key is a key-type refusal. */
    {
      static const CK_BYTE wp256oid[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
      };
      CK_OBJECT_CLASS wpubcls = CKO_PUBLIC_KEY;
      CK_OBJECT_CLASS wprvcls = CKO_PRIVATE_KEY;
      CK_KEY_TYPE wekt = CKK_EC;
      CK_ATTRIBUTE wpubT[] = {
        { CKA_CLASS, &wpubcls, sizeof(wpubcls) },
        { CKA_KEY_TYPE, &wekt, sizeof(wekt) },
        { CKA_EC_PARAMS, (CK_VOID_PTR) wp256oid, sizeof(wp256oid) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
      };
      CK_ATTRIBUTE wprivT[] = {
        { CKA_CLASS, &wprvcls, sizeof(wprvcls) },
        { CKA_KEY_TYPE, &wekt, sizeof(wekt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_WRAP, &bTrue, sizeof(bTrue) },
        { CKA_UNWRAP, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM wkgm;
      CK_OBJECT_HANDLE wecPub = 0, wecPriv = 0;
      wkgm.mechanism = CKM_EC_KEY_PAIR_GEN;
      wkgm.pParameter = NULL_PTR;
      wkgm.ulParameterLen = 0;
      rv = f->C_GenerateKeyPair(wsess, &wkgm, wpubT, 5, wprivT, 6,
                                &wecPub, &wecPriv);
      CHECKC(rv == CKR_OK && wecPub != 0 && wecPriv != 0,
             "wrap EC pair mints");
      probeLen = sizeof(probe);
      rv = f->C_WrapKey(wsess, &wm, wecPriv, targetKey, probe, &probeLen);
      CHECKC(rv == CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
             "wrap with EC key refused");
      {
        CK_OBJECT_HANDLE badw = 0;
        CK_ATTRIBUTE dwtmpl[] = {
          { CKA_CLASS, &ckcls, sizeof(ckcls) },
          { CKA_KEY_TYPE, &akt, sizeof(akt) },
          { CKA_TOKEN, &bFalse, sizeof(bFalse) }
        };
        rv = f->C_UnwrapKey(wsess, &um, wecPriv, blob, blobLen,
                            dwtmpl, 3, &badw);
        CHECKC(rv == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
               "unwrap with EC key refused");
        CHECKC(badw == 0, "refused unwrap writes no handle");
      }
      /* Generic-secret import (the oracle's negotiated wrong-key
       * setup) refuses the same way. */
      {
        CK_BYTE gmat[32];
        CK_OBJECT_HANDLE genKey = 0;
        CK_ATTRIBUTE gtmpl[] = {
          { CKA_CLASS, &ckcls, sizeof(ckcls) },
          { CKA_KEY_TYPE, &gkt, sizeof(gkt) },
          { CKA_TOKEN, &bFalse, sizeof(bFalse) },
          { CKA_WRAP, &bTrue, sizeof(bTrue) },
          { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
          { CKA_VALUE, gmat, sizeof(gmat) }
        };
        memset(gmat, 0x42, sizeof(gmat));
        rv = f->C_CreateObject(wsess, gtmpl, 6, &genKey);
        CHECKC(rv == CKR_OK && genKey != 0, "generic key imports");
        probeLen = sizeof(probe);
        rv = f->C_WrapKey(wsess, &wm, genKey, targetKey, probe, &probeLen);
        CHECKC(rv == CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
               "wrap with generic key refused");
      }
    }
    /* Unwrap into a working key. */
    {
      CK_ATTRIBUTE dtmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM noiv;
      noiv.mechanism = CKM_AES_CBC;
      noiv.pParameter = NULL_PTR;
      noiv.ulParameterLen = 0;
      rv = f->C_UnwrapKey(wsess, &noiv, wrapKey, blob, blobLen,
                          dtmpl, 6, &unwrapped);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "UnwrapKey empty IV refused");
      rv = f->C_UnwrapKey(wsess, &um, wrapKey, blob, blobLen,
                          dtmpl, 6, &unwrapped);
      CHECKC(rv == CKR_OK && unwrapped != 0 && unwrapped != targetKey,
             "unwrap mints a distinct key");
      {
        CK_MECHANISM cem;
        CK_BYTE ct[32];
        CK_BYTE pt[32];
        CK_ULONG ctl = sizeof(ct);
        CK_ULONG ptl = sizeof(pt);
        cem.mechanism = CKM_AES_CBC_PAD;
        cem.pParameter = iv;
        cem.ulParameterLen = sizeof(iv);
        rv = f->C_EncryptInit(wsess, &cem, unwrapped);
        CHECKC(rv == CKR_OK, "unwrapped key encrypts");
        rv = f->C_Encrypt(wsess, (CK_BYTE_PTR) "wrap-proved", 11, ct, &ctl);
        CHECKC(rv == CKR_OK && ctl == 16, "unwrapped encrypt yields 16");
        rv = f->C_DecryptInit(wsess, &cem, targetKey);
        CHECKC(rv == CKR_OK, "target key decrypts");
        rv = f->C_Decrypt(wsess, ct, ctl, pt, &ptl);
        CHECKC(rv == CKR_OK && ptl == 11 &&
                   memcmp(pt, "wrap-proved", 11) == 0,
               "target decrypts unwrapped-key ciphertext");
      }
      blob[blobLen - 1] ^= 0xFF;
      {
        CK_OBJECT_HANDLE bad = 0;
        rv = f->C_UnwrapKey(wsess, &um, wrapKey, blob, blobLen,
                            dtmpl, 6, &bad);
        CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "tampered blob refused");
        CHECKC(bad == 0, "refused unwrap writes no handle");
      }
      blob[blobLen - 1] ^= 0xFF;
    }
    /* AES-KW wrap/unwrap: the 16-byte target wraps to 24 (+8 IV);
     * KWP agrees on block-aligned input and unwraps the same way. */
    {
      CK_ATTRIBUTE kwdtmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM kwm;
      CK_MECHANISM kwum;
      CK_OBJECT_HANDLE kwUnwrapped = 0;
      CK_BYTE kwblob[64];
      CK_ULONG kwblobLen;
      kwm.mechanism = CKM_AES_KEY_WRAP;
      kwm.pParameter = NULL_PTR;
      kwm.ulParameterLen = 0;
      kwum = kwm;
      kwblobLen = 0;
      rv = f->C_WrapKey(wsess, &kwm, wrapKey, targetKey, NULL_PTR, &kwblobLen);
      CHECKC(rv == CKR_OK && kwblobLen == 24, "kw size query reports 24");
      kwblobLen = 16;
      rv = f->C_WrapKey(wsess, &kwm, wrapKey, targetKey, kwblob, &kwblobLen);
      CHECKC(rv == CKR_BUFFER_TOO_SMALL && kwblobLen == 24,
             "short kw buffer reports 24");
      kwblobLen = sizeof(kwblob);
      rv = f->C_WrapKey(wsess, &kwm, wrapKey, targetKey, kwblob, &kwblobLen);
      CHECKC(rv == CKR_OK && kwblobLen == 24, "kw wrap yields 24 bytes");
      rv = f->C_UnwrapKey(wsess, &kwum, wrapKey, kwblob, kwblobLen,
                          kwdtmpl, 6, &kwUnwrapped);
      CHECKC(rv == CKR_OK && kwUnwrapped != 0 && kwUnwrapped != targetKey,
             "kw unwrap mints a distinct key");
      kwblob[kwblobLen - 1] ^= 0xFF;
      {
        CK_OBJECT_HANDLE bad = 0;
        rv = f->C_UnwrapKey(wsess, &kwum, wrapKey, kwblob, kwblobLen,
                            kwdtmpl, 6, &bad);
        CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "tampered kw blob refused");
        CHECKC(bad == 0, "refused kw unwrap writes no handle");
      }
      kwblob[kwblobLen - 1] ^= 0xFF;
    }
    /* AES-KWP object path: same 24-byte framing on aligned input. */
    {
      CK_ATTRIBUTE kwpdtmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &akt, sizeof(akt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
      };
      CK_MECHANISM kwpm;
      CK_OBJECT_HANDLE kwpUnwrapped = 0;
      CK_BYTE kwpblob[64];
      CK_ULONG kwpblobLen = sizeof(kwpblob);
      kwpm.mechanism = CKM_AES_KEY_WRAP_KWP;
      kwpm.pParameter = NULL_PTR;
      kwpm.ulParameterLen = 0;
      rv = f->C_WrapKey(wsess, &kwpm, wrapKey, targetKey, kwpblob, &kwpblobLen);
      CHECKC(rv == CKR_OK && kwpblobLen == 24, "kwp wrap yields 24 bytes");
      rv = f->C_UnwrapKey(wsess, &kwpm, wrapKey, kwpblob, kwpblobLen,
                          kwpdtmpl, 6, &kwpUnwrapped);
      CHECKC(rv == CKR_OK && kwpUnwrapped != 0 && kwpUnwrapped != targetKey,
             "kwp unwrap mints a distinct key");
    }
    /* HKDF-subset derive: expand-only, empty salt, SHA-256 PRF. */
    {
      CK_ATTRIBUTE ktmpl[] = {
        { CKA_CLASS, &ckcls, sizeof(ckcls) },
        { CKA_KEY_TYPE, &gkt, sizeof(gkt) },
        { CKA_VALUE_LEN, &dlen, sizeof(dlen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      CK_BYTE valA[32];
      CK_BYTE valB[32];
      CK_BYTE saltByte = 0;
      CK_ATTRIBUTE get[1];
      dhkdf.mechanism = CKM_HKDF_DERIVE;
      dhkdf.pParameter = &hkdf;
      dhkdf.ulParameterLen = sizeof(hkdf);
      hkdf.bExtract = CK_FALSE;
      hkdf.bExpand = CK_TRUE;
      hkdf.prfHashMechanism = CKM_SHA256_HMAC;
      hkdf.ulSaltType = CKF_HKDF_SALT_NULL;
      hkdf.pSalt = NULL_PTR;
      hkdf.ulSaltLen = 0;
      hkdf.hSaltKey = 0;
      hkdf.pInfo = infoA;
      hkdf.ulInfoLen = sizeof(infoA);
      rv = f->C_DeriveKey(wsess, NULL_PTR, sealedKey, ktmpl, 5, &derived);
      CHECKC(rv == CKR_ARGUMENTS_BAD, "DeriveKey NULL mech refused");
      rv = f->C_DeriveKey(wsess, &dhkdf, sealedKey, ktmpl, 5, &derived);
      CHECKC(rv == CKR_OK && derived != 0, "HKDF derive ok");
      get[0].type = CKA_VALUE;
      get[0].pValue = valA;
      get[0].ulValueLen = sizeof(valA);
      rv = f->C_GetAttributeValue(wsess, derived, get, 1);
      CHECKC(rv == CKR_OK && get[0].ulValueLen == 32,
             "derived VALUE reads 32 bytes");
      hkdf.pInfo = infoB;
      hkdf.ulInfoLen = sizeof(infoB);
      rv = f->C_DeriveKey(wsess, &dhkdf, sealedKey, ktmpl, 5, &derived2);
      CHECKC(rv == CKR_OK && derived2 != 0 && derived2 != derived,
             "second info derives distinct key");
      get[0].type = CKA_VALUE;
      get[0].pValue = valB;
      get[0].ulValueLen = sizeof(valB);
      rv = f->C_GetAttributeValue(wsess, derived2, get, 1);
      CHECKC(rv == CKR_OK && memcmp(valA, valB, 32) != 0,
             "distinct infos derive distinct bytes");
      hkdf.bExtract = CK_TRUE;
      {
        CK_OBJECT_HANDLE bad = 0;
        rv = f->C_DeriveKey(wsess, &dhkdf, sealedKey, ktmpl, 5, &bad);
        CHECKC(rv == CKR_ARGUMENTS_BAD, "extract phase refused");
        CHECKC(bad == 0, "refused derive writes no handle");
      }
      hkdf.bExtract = CK_FALSE;
      hkdf.prfHashMechanism = CKM_SHA512_HMAC;
      {
        CK_OBJECT_HANDLE bad = 0;
        rv = f->C_DeriveKey(wsess, &dhkdf, sealedKey, ktmpl, 5, &bad);
        CHECKC(rv == CKR_ARGUMENTS_BAD, "non-SHA256 PRF refused");
      }
      hkdf.prfHashMechanism = CKM_SHA256_HMAC;
      hkdf.ulSaltType = CKF_HKDF_SALT_DATA;
      hkdf.pSalt = &saltByte;
      hkdf.ulSaltLen = 1;
      {
        CK_OBJECT_HANDLE bad = 0;
        rv = f->C_DeriveKey(wsess, &dhkdf, sealedKey, ktmpl, 5, &bad);
        CHECKC(rv == CKR_ARGUMENTS_BAD, "non-empty salt refused");
      }
      decdh.mechanism = CKM_ECDH1_DERIVE;
      decdh.pParameter = NULL_PTR;
      decdh.ulParameterLen = 0;
      {
        CK_OBJECT_HANDLE bad = 0;
        /* ECDH is wired now: the AES wrap key refuses typed
         * (key-type check runs before parameter shape). */
        rv = f->C_DeriveKey(wsess, &decdh, sealedKey, ktmpl, 5, &bad);
        CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT,
               "ECDH with AES base refused typed");
        CHECKC(bad == 0, "refused ECDH derive writes no handle");
      }
    }
    rv = f->C_CloseSession(wsess);
    CHECKC(rv == CKR_OK, "wrap session closes");
  }
  /* ---- objects are real: create/get/copy/find/destroy ---- */
  {
    CK_OBJECT_CLASS klass = CKO_DATA;
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_OBJECT_HANDLE dataObj = 0, copyObj = 0, privObj = 0;
    CK_ATTRIBUTE tmpl[] = {
      { CKA_CLASS, &klass, sizeof(klass) },
      { CKA_TOKEN, &no, sizeof(no) },
      { CKA_PRIVATE, &no, sizeof(no) },
      { CKA_LABEL, "s2-data", 7 },
      { CKA_VALUE, "payload-1", 9 },
    };
    rv = f->C_CreateObject(sess, tmpl, 5, &dataObj);
    CHECKC(rv == CKR_OK && dataObj != 0, "CreateObject data ok");
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE g[] = {
        { CKA_LABEL, NULL_PTR, 0 },
        { CKA_VALUE, buf, sizeof(buf) },
      };
      rv = f->C_GetAttributeValue(sess, dataObj, g, 2);
      CHECKC(rv == CKR_OK && g[0].ulValueLen == 7 &&
                 g[1].ulValueLen == 9 && memcmp(buf, "payload-1", 9) == 0,
             "GetAttributeValue reads label+value");
      g[1].pValue = buf;
      g[1].ulValueLen = 4;
      rv = f->C_GetAttributeValue(sess, dataObj, &g[1], 1);
      CHECKC(rv == CKR_BUFFER_TOO_SMALL &&
                 g[1].ulValueLen == CK_UNAVAILABLE_INFORMATION,
             "short value buffer reports the unavailable sentinel");
    }
    {
      CK_ULONG bits = 0;
      CK_ATTRIBUTE g[] = { { CKA_MODULUS_BITS, &bits, sizeof(bits) } };
      rv = f->C_GetAttributeValue(sess, dataObj, g, 1);
      CHECKC(rv == CKR_ATTRIBUTE_TYPE_INVALID &&
                 g[0].ulValueLen == CK_UNAVAILABLE_INFORMATION,
             "missing attr type invalid, len -1");
    }
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE g[] = { { 0xFFFFFFFEUL, buf, sizeof(buf) } };
      rv = f->C_GetAttributeValue(sess, dataObj, g, 1);
      if (!isProxy) {
        CHECKC(rv == CKR_ATTRIBUTE_TYPE_INVALID &&
                   g[0].ulValueLen == CK_UNAVAILABLE_INFORMATION,
               "unknown attr id invalid, len -1");
      } else {
        /* The shim rejects unknown attr ids itself (ARGUMENTS_BAD,
         * length untouched) without forwarding. */
        CHECKC(rv == CKR_ARGUMENTS_BAD && g[0].ulValueLen == sizeof(buf),
               "proxied unknown attr refused, len kept");
      }
    }
    {
      CK_ATTRIBUTE ctmpl[] = { { CKA_LABEL, "s2-copy", 7 } };
      rv = f->C_CopyObject(sess, dataObj, ctmpl, 1, &copyObj);
      CHECKC(rv == CKR_OK && copyObj != 0 && copyObj != dataObj,
             "CopyObject ok, distinct handle");
    }
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE g[] = { { CKA_LABEL, buf, sizeof(buf) } };
      rv = f->C_GetAttributeValue(sess, copyObj, g, 1);
      CHECKC(rv == CKR_OK && g[0].ulValueLen == 7 &&
                 memcmp(buf, "s2-copy", 7) == 0,
             "copy carries the new label");
    }
    {
      CK_ATTRIBUTE ptmpl[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &no, sizeof(no) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, "s2-priv", 7 },
      };
      CK_BYTE buf[64];
      CK_ATTRIBUTE g[] = { { CKA_LABEL, buf, sizeof(buf) } };
      rv = f->C_CreateObject(sess, ptmpl, 4, &privObj);
      CHECKC(rv == CKR_USER_NOT_LOGGED_IN,
             "private create refused while logged out");
      rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
      CHECKC(rv == CKR_OK, "login mints private");
      rv = f->C_CreateObject(sess, ptmpl, 4, &privObj);
      CHECKC(rv == CKR_OK && privObj != 0, "private object created");
      rv = f->C_Logout(sess);
      CHECKC(rv == CKR_OK, "logout after private create");
      rv = f->C_GetAttributeValue(sess, privObj, g, 1);
      CHECKC(rv == CKR_OBJECT_HANDLE_INVALID,
             "private object unaddressable while logged out");
    }
    {
      CK_OBJECT_HANDLE found[8];
      CK_ULONG nfound = 0;
      CK_ATTRIBUTE match[] = { { CKA_LABEL, "s2-data", 7 } };
      rv = f->C_FindObjectsInit(sess, match, 1);
      CHECKC(rv == CKR_OK, "FindObjectsInit label ok");
      rv = f->C_FindObjectsInit(sess, match, 1);
      CHECKC(rv == CKR_OPERATION_ACTIVE, "double find-init active");
      nfound = 8;
      rv = f->C_FindObjects(sess, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 1 && found[0] == dataObj,
             "find by label yields the object");
      nfound = 8;
      rv = f->C_FindObjects(sess, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 0, "find cursor exhausts");
      rv = f->C_FindObjectsFinal(sess);
      CHECKC(rv == CKR_OK, "FindObjectsFinal ok");
      rv = f->C_FindObjectsFinal(sess);
      CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
             "double find-final uninitialized");
      nfound = 8;
      rv = f->C_FindObjects(sess, found, 8, &nfound);
      CHECKC(rv == CKR_OPERATION_NOT_INITIALIZED,
             "find without init uninitialized");
    }
    {
      CK_OBJECT_HANDLE found[8];
      CK_ULONG nfound = 2;
      int sawData = 0, sawCopy = 0;
      CK_ULONG i = 0;
      rv = f->C_FindObjectsInit(sess, NULL_PTR, 0);
      CHECKC(rv == CKR_OK, "match-all find-init ok");
      rv = f->C_FindObjects(sess, found, 2, &nfound);
      CHECKC(rv == CKR_OK && nfound == 2, "match-all page one has two");
      for (i = 0; i < nfound; i++) {
        if (found[i] == dataObj) {
          sawData = 1;
        }
        if (found[i] == copyObj) {
          sawCopy = 1;
        }
      }
      nfound = 8;
      rv = f->C_FindObjects(sess, found, 8, &nfound);
      CHECKC(rv == CKR_OK && nfound == 0, "match-all page two empty");
      CHECKC(sawData && sawCopy, "match-all sees data+copy, not private");
      rv = f->C_FindObjectsFinal(sess);
      CHECKC(rv == CKR_OK, "match-all final ok");
    }
    {
      CK_OBJECT_HANDLE bad = 0;
      CK_ATTRIBUTE btmpl[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { 0xFFFFFFFEUL, "x", 1 },
      };
      rv = f->C_CreateObject(sess, btmpl, 2, &bad);
      CHECKC(rv == CKR_ATTRIBUTE_TYPE_INVALID,
             "unknown template attr rejected");
    }
    {
      CK_OBJECT_HANDLE bad = 0;
      CK_ULONG wide = 1;
      CK_ATTRIBUTE btmpl[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &wide, sizeof(wide) },
      };
      rv = f->C_CreateObject(sess, btmpl, 2, &bad);
      CHECKC(rv == CKR_TEMPLATE_INCONSISTENT, "misshapen value rejected");
    }
    {
      CK_SESSION_HANDLE rosess = 0;
      CK_OBJECT_HANDLE bad = 0;
      rv = f->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                            &rosess);
      if (rv == CKR_SLOT_ID_INVALID) {
        CK_SLOT_ID psl[8];
        CK_ULONG pn = 8;
        if (f->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
          rv = f->C_OpenSession(psl[0], CKF_SERIAL_SESSION, NULL_PTR,
                                NULL_PTR, &rosess);
        }
      }
      CHECKC(rv == CKR_OK && rosess != 0, "RO session for owner-dimension check");
      rv = f->C_CreateObject(rosess, tmpl, 5, &bad);
      CHECKC(rv == CKR_OK && bad != 0, "RO session-object create admitted");
      {
        CK_BBOOL yes = CK_TRUE;
        CK_ATTRIBUTE ttmpl[] = {
          { CKA_CLASS, &klass, sizeof(klass) },
          { CKA_TOKEN, &yes, sizeof(yes) },
          { CKA_PRIVATE, &no, sizeof(no) },
          { CKA_LABEL, "ro-tok", 6 },
          { CKA_VALUE, "payload-1", 9 },
        };
        CK_OBJECT_HANDLE tbad = 0;
        rv = f->C_CreateObject(rosess, ttmpl, 5, &tbad);
        CHECKC(rv == CKR_SESSION_READ_ONLY, "RO token-object create refused");
      }
      rv = f->C_CloseSession(rosess);
      CHECKC(rv == CKR_OK, "RO session closed");
    }
    /* ---- key import: RSA/EC component templates create keys ---- */
    {
      /* Pinned OpenSSL 4.0.2 vectors (shared with KeyImportSpec). */
      static const char hn[] =
      "bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e6f9022cd2b4f"
      "efd66e575e7043004afef1e4916177cea097cef02d4f09de587d869840cd75ec"
      "a6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386009d54d13f1b"
      "1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c9b64981300e4"
      "a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d577fe8533717"
      "9f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451ee15fd44b42a"
      "5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a055327d339855e"
      "838995295160067a417cc8c3095ee012bf078da33c71becae36b9805c174f357";
      static const char he[] =
      "010001";
      static const char hd[] =
      "02147aaaa8fabcedbe219165e22478ac626079befb92b2fa0f1960886a8088b9"
      "f5765966b4fde16a1ae6d1a8b6eb9f1b4e0468e43f31f97daf167fef9f363d29"
      "7144e4558adf855092b47bfc83d1a7b51cf40ba449e9d9c34cb5f4181788b162"
      "f0f78db4854d934b91f6a25079ddbdf5722847ea70cff8e62a540152e3bec287"
      "3598079bf1965083cca686d500ab2867c43db553dd2894a3014fa30814f58966"
      "b7f91e71b9c6928f41d22587daa3a939b409b9aeac3765404b0b3a890000c2e3"
      "480d90950529f73df1340f69cc8be3c69def997524a3883cc618f51a81130842"
      "f094b95699d093acb3e8c59a9a65b968101f6220638265e398f8f65ba6363ca5";
      static const char hp[] =
      "f38edb79d7c425b930bee769f17aa3cc565f6e0a72b7fd0c734a0257960213f5"
      "c5c5d16887e80d0d8c9136daa855e26e38319f7cd5f454b875e9eff1c9a6dc88"
      "753a65d825d079d1fd9b8d1843e250793279877e1db7bd932b09473a1973ce71"
      "0f5179baf192a17052a66c5247205bdad49fb48938b6590d5f2154820337498b";
      static const char hq[] =
      "c8e8439d64764eaff4f6bf45bc56df3280d3c5aeedae00f0099f3d169db75f3a"
      "0105900eef944f120f0d49d63d623e07b6feafa043914bf8e4ae243a9f82b853"
      "dc1e347b262a250423d1f53f097cdce6677813a277f8eca15b5a61acb08bbdc2"
      "042a0457492f09488ab22936aa8e098798484a230f3c4d27294589d4c8a1bee5";
      static const char hdp[] =
      "17e28b9d804e6910a73a21819f3fd2ae684e05819acc76517140f1c7db1b2b0f"
      "f02c3d240e27f097c2903f1be4643fc765556079a295ca7528831f97cb99c488"
      "d14e3fcc99b0bf319bb85476ebb95700fbb5355765dcae07afb1c23d6d5f9100"
      "3f6b530fc53f06fbf7ef0032756d33f4dae32a96466c83812f321a9281743b8f";
      static const char hdq[] =
      "80b900096a02bb2bd5e1fa6f2ddae32ab28bfd0eb54e555f766ac673251e062f"
      "5dd43896b93de6e3852d586fa1e8be21a747cb32fdd7ac3b8e195d310a5e70c7"
      "9a32e8213734ad7ed78c807ba112955e325127136396e3d606780438e6ecc1e9"
      "fb4d0876fc76dc95d3f78e9c6dee8f80873b59f4d8a02436c124c2c8c8bb8959";
      static const char hqi[] =
      "3cefd2574cbb2056d55f71c3fe82090a9797c6c038d1ef045e0373081801f4e4"
      "68f7822b9580bcd21aac3c601a330ca745978cd01761cbccf29201086defab1f"
      "08ec5024b60b79ed839dbf43c9c35a07da5cf8163fc4c57a1e06b20378077dab"
      "fb54e39d56bf2a4d478187829ec00236001f1503a903482246a21aac1c04ae4f";
      static const char hscalar[] =
      "5bc5fc2e1cb344d11de202ea057cbfd5da5f9a9a54a83fda363e5742b044366c";
      static const char hpoint[] =
      "044104a113ffac941b89a293f5bb308496c60f74732c92b5724a97191ba3f76d"
      "afa9b00ba279852742b80f7e8bc51f7fd41b368d1c611c391a4abd0559ddf16b"
      "63ee01";      CK_OBJECT_CLASS prvcls = CKO_PRIVATE_KEY, pubcls = CKO_PUBLIC_KEY;
      CK_KEY_TYPE rsakt = CKK_RSA, eckt = CKK_EC;
      CK_BYTE n[256], e[8], d[256];
      CK_BYTE p[128], q[128], dp[128], dq[128], qi[128];
      CK_BYTE scalar[32], point[67];
      CK_BYTE rparams[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
      };
      CK_OBJECT_HANDLE rsaPriv = 0, rsaPub = 0, ecPriv = 0, ecPub = 0;
      CHECKC(hex_to_bytes(hn, n, sizeof(n)) == sizeof(n), "fixture n parses");
      CHECKC(hex_to_bytes(he, e, sizeof(e)) == 3, "fixture e parses");
      CHECKC(hex_to_bytes(hd, d, sizeof(d)) == sizeof(d), "fixture d parses");
      CHECKC(hex_to_bytes(hp, p, sizeof(p)) == sizeof(p), "fixture p parses");
      CHECKC(hex_to_bytes(hq, q, sizeof(q)) == sizeof(q), "fixture q parses");
      CHECKC(hex_to_bytes(hdp, dp, sizeof(dp)) == sizeof(dp), "fixture dp parses");
      CHECKC(hex_to_bytes(hdq, dq, sizeof(dq)) == sizeof(dq), "fixture dq parses");
      CHECKC(hex_to_bytes(hqi, qi, sizeof(qi)) == sizeof(qi), "fixture qi parses");
      CHECKC(hex_to_bytes(hscalar, scalar, sizeof(scalar)) == sizeof(scalar),
             "fixture scalar parses");
      CHECKC(hex_to_bytes(hpoint, point, sizeof(point)) == sizeof(point),
             "fixture point parses");
      {
        CK_ATTRIBUTE rtmpl[] = {
          { CKA_CLASS, &prvcls, sizeof(prvcls) },
          { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_SENSITIVE, &no, sizeof(no) },
          { CKA_EXTRACTABLE, &yes, sizeof(yes) },
          { CKA_MODULUS, n, sizeof(n) },
          { CKA_PUBLIC_EXPONENT, e, 3 },
          { CKA_PRIVATE_EXPONENT, d, sizeof(d) },
          { CKA_PRIME_1, p, sizeof(p) },
          { CKA_PRIME_2, q, sizeof(q) },
          { CKA_EXPONENT_1, dp, sizeof(dp) },
          { CKA_EXPONENT_2, dq, sizeof(dq) },
          { CKA_COEFFICIENT, qi, sizeof(qi) },
        };
        CK_ATTRIBUTE g[] = { { CKA_MODULUS, NULL_PTR, 0 } };
        CK_BYTE got[256];
        rv = f->C_CreateObject(sess, rtmpl, 13, &rsaPriv);
        CHECKC(rv == CKR_OK && rsaPriv != 0, "RSA private import ok");
        g[0].pValue = got;
        g[0].ulValueLen = sizeof(got);
        rv = f->C_GetAttributeValue(sess, rsaPriv, g, 1);
        CHECKC(rv == CKR_OK && g[0].ulValueLen == sizeof(n) &&
                   memcmp(got, n, sizeof(n)) == 0,
               "RSA modulus reads back");
      }
      {
        CK_ATTRIBUTE rtmpl[] = {
          { CKA_CLASS, &pubcls, sizeof(pubcls) },
          { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_MODULUS, n, sizeof(n) },
          { CKA_PUBLIC_EXPONENT, e, 3 },
        };
        rv = f->C_CreateObject(sess, rtmpl, 5, &rsaPub);
        CHECKC(rv == CKR_OK && rsaPub != 0, "RSA public import ok");
      }
      /* Native struct params: real CK_RSA_PKCS_PSS_PARAMS and
       * CK_RSA_PKCS_OAEP_PARAMS through the Init planners. */
      {
        CK_ATTRIBUTE pssPrivT[] = {
          { CKA_CLASS, &prvcls, sizeof(prvcls) },
          { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_SENSITIVE, &no, sizeof(no) },
          { CKA_EXTRACTABLE, &yes, sizeof(yes) },
          { CKA_SIGN, &yes, sizeof(yes) },
          { CKA_DECRYPT, &yes, sizeof(yes) },
          { CKA_DERIVE, &yes, sizeof(yes) },
          { CKA_MODULUS, n, sizeof(n) },
          { CKA_PUBLIC_EXPONENT, e, 3 },
          { CKA_PRIVATE_EXPONENT, d, sizeof(d) },
          { CKA_PRIME_1, p, sizeof(p) },
          { CKA_PRIME_2, q, sizeof(q) },
          { CKA_EXPONENT_1, dp, sizeof(dp) },
          { CKA_EXPONENT_2, dq, sizeof(dq) },
          { CKA_COEFFICIENT, qi, sizeof(qi) },
        };
        CK_ATTRIBUTE pssPubT[] = {
          { CKA_CLASS, &pubcls, sizeof(pubcls) },
          { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_VERIFY, &yes, sizeof(yes) },
          { CKA_ENCRYPT, &yes, sizeof(yes) },
          { CKA_MODULUS, n, sizeof(n) },
          { CKA_PUBLIC_EXPONENT, e, 3 },
        };
        CK_OBJECT_HANDLE pssPriv = 0, pssPub = 0;
        CK_RSA_PKCS_PSS_PARAMS pss;
        CK_RSA_PKCS_OAEP_PARAMS oaep;
        CK_MECHANISM sm, em;
        CK_BYTE psig[256], ctext[256], back[256];
        CK_ULONG psigLen, ctextLen, backLen;
        CK_BYTE labelL[] = { 'L' }, labelX[] = { 'X' };
        CK_BYTE msg[] = { 'a', 'b', 'c' };
        /* Deliberately not block-aligned (27 bytes): OAEP inputs
         * are length-bounded, never block-framed. */
        CK_BYTE plain[27] = { 'O','A','E','P',' ','p','a','r','a','m',
                              'e','t','e','r','-','f','i','d','e','l',
                              'i','t','y',' ','p','r','o' };
        CK_BYTE big[200] = { 0 };
        rv = f->C_CreateObject(sess, pssPrivT, 16, &pssPriv);
        CHECKC(rv == CKR_OK && pssPriv != 0, "PSS RSA private imports");
        rv = f->C_CreateObject(sess, pssPubT, 7, &pssPub);
        CHECKC(rv == CKR_OK && pssPub != 0, "PSS RSA public imports");
        pss.hashAlg = CKM_SHA256;
        pss.mgf = CKG_MGF1_SHA256;
        pss.sLen = 32;
        sm.mechanism = CKM_RSA_PKCS_PSS;
        sm.pParameter = &pss;
        sm.ulParameterLen = sizeof(pss);
        rv = f->C_SignInit(sess, &sm, pssPriv);
        CHECKC(rv == CKR_OK, "PSS native-struct SignInit ok");
        psigLen = sizeof(psig);
        rv = f->C_Sign(sess, msg, sizeof(msg), psig, &psigLen);
        CHECKC(rv == CKR_OK && psigLen == 256, "PSS sign yields 256 bytes");
        rv = f->C_VerifyInit(sess, &sm, pssPub);
        CHECKC(rv == CKR_OK, "PSS native-struct VerifyInit ok");
        rv = f->C_Verify(sess, msg, sizeof(msg), psig, psigLen);
        CHECKC(rv == CKR_OK, "PSS verify of its own signature ok");
        oaep.hashAlg = CKM_SHA256;
        oaep.mgf = CKG_MGF1_SHA256;
        oaep.source = CKZ_DATA_SPECIFIED;
        oaep.pSourceData = NULL_PTR;
        oaep.ulSourceDataLen = 0;
        em.mechanism = CKM_RSA_PKCS_OAEP;
        em.pParameter = &oaep;
        em.ulParameterLen = sizeof(oaep);
        rv = f->C_EncryptInit(sess, &em, pssPub);
        CHECKC(rv == CKR_OK, "OAEP native-struct EncryptInit ok");
        ctextLen = sizeof(ctext);
        rv = f->C_Encrypt(sess, plain, sizeof(plain), ctext, &ctextLen);
        CHECKC(rv == CKR_OK && ctextLen == 256, "OAEP encrypt yields 256 bytes");
        rv = f->C_DecryptInit(sess, &em, pssPriv);
        CHECKC(rv == CKR_OK, "OAEP native-struct DecryptInit ok");
        backLen = sizeof(back);
        rv = f->C_Decrypt(sess, ctext, ctextLen, back, &backLen);
        CHECKC(rv == CKR_OK && backLen == sizeof(plain) &&
                   memcmp(back, plain, sizeof(plain)) == 0,
               "OAEP decrypt round-trips");
        /* Labeled OAEP: the same label round-trips, a wrong label
         * refuses (this leg proves the label pointer is chased). */
        oaep.pSourceData = labelL;
        oaep.ulSourceDataLen = sizeof(labelL);
        rv = f->C_EncryptInit(sess, &em, pssPub);
        CHECKC(rv == CKR_OK, "labeled OAEP EncryptInit ok");
        ctextLen = sizeof(ctext);
        rv = f->C_Encrypt(sess, plain, sizeof(plain), ctext, &ctextLen);
        CHECKC(rv == CKR_OK, "labeled OAEP encrypt ok");
        rv = f->C_DecryptInit(sess, &em, pssPriv);
        CHECKC(rv == CKR_OK, "labeled OAEP DecryptInit ok");
        backLen = sizeof(back);
        rv = f->C_Decrypt(sess, ctext, ctextLen, back, &backLen);
        CHECKC(rv == CKR_OK && backLen == sizeof(plain) &&
                   memcmp(back, plain, sizeof(plain)) == 0,
               "labeled OAEP decrypt round-trips");
        oaep.pSourceData = labelX;
        oaep.ulSourceDataLen = sizeof(labelX);
        rv = f->C_DecryptInit(sess, &em, pssPriv);
        CHECKC(rv == CKR_OK, "wrong-label OAEP DecryptInit ok");
        backLen = sizeof(back);
        rv = f->C_Decrypt(sess, ctext, ctextLen, back, &backLen);
        CHECKC(rv != CKR_OK, "wrong-label OAEP decrypt refuses");
        /* Over-long input refuses (backend k-2*hLen-2 bound:
         * 200 > 256-64-2). */
        oaep.pSourceData = NULL_PTR;
        oaep.ulSourceDataLen = 0;
        rv = f->C_EncryptInit(sess, &em, pssPub);
        CHECKC(rv == CKR_OK, "over-long OAEP EncryptInit ok");
        ctextLen = sizeof(ctext);
        rv = f->C_Encrypt(sess, big, sizeof(big), ctext, &ctextLen);
        CHECKC(rv != CKR_OK, "over-long OAEP encrypt refuses");
        /* ECDH + SHA-KDF derive through the opaque intake. */
        {
          CK_OBJECT_CLASS seccls = CKO_SECRET_KEY;
          CK_KEY_TYPE genkt = CKK_GENERIC_SECRET;
          CK_ULONG vlen = 32;
          CK_ATTRIBUTE ecBaseT[] = {
            { CKA_CLASS, &prvcls, sizeof(prvcls) },
            { CKA_KEY_TYPE, &eckt, sizeof(eckt) },
            { CKA_TOKEN, &no, sizeof(no) },
            { CKA_SENSITIVE, &no, sizeof(no) },
            { CKA_EXTRACTABLE, &yes, sizeof(yes) },
            { CKA_DERIVE, &yes, sizeof(yes) },
            { CKA_EC_PARAMS, rparams, sizeof(rparams) },
            { CKA_VALUE, scalar, sizeof(scalar) },
          };
          CK_BYTE genval[32] = { 'b','a','s','e','-','m','a','t','e','r','i','a','l','!','!','!',
                                 '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
          CK_ATTRIBUTE genBaseT[] = {
            { CKA_CLASS, &seccls, sizeof(seccls) },
            { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
            { CKA_TOKEN, &no, sizeof(no) },
            { CKA_DERIVE, &yes, sizeof(yes) },
            { CKA_VALUE, genval, sizeof(genval) },
          };
          CK_ATTRIBUTE dtmpl[] = {
            { CKA_CLASS, &seccls, sizeof(seccls) },
            { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
            { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
            { CKA_TOKEN, &no, sizeof(no) },
            { CKA_SENSITIVE, &no, sizeof(no) },
            { CKA_EXTRACTABLE, &yes, sizeof(yes) },
          };
          CK_OBJECT_HANDLE ecBase = 0, genBase = 0;
          CK_OBJECT_HANDLE d1 = 0, d2 = 0, d3 = 0, d4 = 0, d5 = 0;
          CK_ECDH1_DERIVE_PARAMS ecdh;
          CK_MECHANISM dm, km, shm;
          CK_BYTE sec1[32], sec2[32], kd1[32], kd2[32], dgst[32];
          CK_ULONG secLen, secLen2, kdLen, kdLen2, dgstLen;
          CK_ATTRIBUTE gsec[] = { { CKA_VALUE, sec1, sizeof(sec1) } };
          CK_ATTRIBUTE gsec2[] = { { CKA_VALUE, sec2, sizeof(sec2) } };
          CK_ATTRIBUTE gkd[] = { { CKA_VALUE, kd1, sizeof(kd1) } };
          CK_ATTRIBUTE gkd2[] = { { CKA_VALUE, kd2, sizeof(kd2) } };
          CK_BYTE garbage[65] = { 0 };
          CK_MECHANISM badm;
          rv = f->C_CreateObject(sess, ecBaseT, 8, &ecBase);
          CHECKC(rv == CKR_OK && ecBase != 0, "ECDH base imports");
          /* The fixture point is DER-wrapped (04 41 || raw); the
           * peer travels as the raw 65-byte point. */
          ecdh.kdf = CKD_NULL;
          ecdh.ulSharedDataLen = 0;
          ecdh.pSharedData = NULL_PTR;
          ecdh.ulPublicDataLen = sizeof(point) - 2;
          ecdh.pPublicData = point + 2;
          dm.mechanism = CKM_ECDH1_DERIVE;
          dm.pParameter = &ecdh;
          dm.ulParameterLen = sizeof(ecdh);
          rv = f->C_DeriveKey(sess, &dm, ecBase, dtmpl, 6, &d1);
          CHECKC(rv == CKR_OK && d1 != 0, "ECDH derive ok");
          secLen = sizeof(sec1);
          gsec[0].ulValueLen = secLen;
          rv = f->C_GetAttributeValue(sess, d1, gsec, 1);
          CHECKC(rv == CKR_OK && gsec[0].ulValueLen == 32,
                 "ECDH secret reads 32 bytes");
          rv = f->C_DeriveKey(sess, &dm, ecBase, dtmpl, 6, &d2);
          CHECKC(rv == CKR_OK && d2 != 0, "ECDH derive replays");
          secLen2 = sizeof(sec2);
          gsec2[0].ulValueLen = secLen2;
          rv = f->C_GetAttributeValue(sess, d2, gsec2, 1);
          CHECKC(rv == CKR_OK && gsec2[0].ulValueLen == 32 &&
                     memcmp(sec1, sec2, 32) == 0,
                 "ECDH secret deterministic");
          /* Wrong-typed base refuses before params are examined. */
          badm.mechanism = CKM_ECDH1_DERIVE;
          badm.pParameter = garbage;
          badm.ulParameterLen = sizeof(garbage);
          rv = f->C_DeriveKey(sess, &badm, pssPriv, dtmpl, 6, &d3);
          CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT && d3 == 0,
                 "ECDH with RSA base and garbage params refused typed");
          rv = f->C_DeriveKey(sess, &dm, pssPriv, dtmpl, 6, &d3);
          CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT && d3 == 0,
                 "ECDH with RSA base and valid params refused typed");
          rv = f->C_DestroyObject(sess, d2);
          CHECKC(rv == CKR_OK, "second secret destroyed");
          km.mechanism = CKM_SHA3_256_KEY_DERIVE;
          km.pParameter = NULL_PTR;
          km.ulParameterLen = 0;
          rv = f->C_DeriveKey(sess, &km, d2, dtmpl, 6, &d4);
          CHECKC(rv == CKR_KEY_HANDLE_INVALID && d4 == 0,
                 "derive with destroyed base refused typed");
          rv = f->C_CreateObject(sess, genBaseT, 5, &genBase);
          CHECKC(rv == CKR_OK && genBase != 0, "KDF base imports");
          rv = f->C_DeriveKey(sess, &km, genBase, dtmpl, 6, &d3);
          CHECKC(rv == CKR_OK && d3 != 0, "SHA3-256 derive ok");
          kdLen = sizeof(kd1);
          gkd[0].ulValueLen = kdLen;
          rv = f->C_GetAttributeValue(sess, d3, gkd, 1);
          CHECKC(rv == CKR_OK && gkd[0].ulValueLen == 32,
                 "SHA3-256 derived value reads 32 bytes");
          rv = f->C_DeriveKey(sess, &km, genBase, dtmpl, 6, &d4);
          CHECKC(rv == CKR_OK && d4 != 0, "SHA3-256 derive replays");
          kdLen2 = sizeof(kd2);
          gkd2[0].ulValueLen = kdLen2;
          rv = f->C_GetAttributeValue(sess, d4, gkd2, 1);
          CHECKC(rv == CKR_OK && gkd2[0].ulValueLen == 32 &&
                     memcmp(kd1, kd2, 32) == 0,
                 "SHA3-256 derived value deterministic");
          rv = f->C_DeriveKey(sess, &km, ecBase, dtmpl, 6, &d5);
          CHECKC(rv == CKR_KEY_TYPE_INCONSISTENT && d5 == 0,
                 "SHA3-256 derive with EC base refused typed");
          /* Token self-consistency: derived == Digest(base). */
          shm.mechanism = CKM_SHA3_256;
          shm.pParameter = NULL_PTR;
          shm.ulParameterLen = 0;
          rv = f->C_DigestInit(sess, &shm);
          CHECKC(rv == CKR_OK, "SHA3-256 DigestInit ok");
          dgstLen = sizeof(dgst);
          rv = f->C_Digest(sess, genval, sizeof(genval), dgst, &dgstLen);
          CHECKC(rv == CKR_OK && dgstLen == 32 && memcmp(dgst, kd1, 32) == 0,
                 "SHA3-256 derived equals token digest");
        }
      }
      {
        CK_ATTRIBUTE ptmpl[] = {
          { CKA_CLASS, &prvcls, sizeof(prvcls) },
          { CKA_KEY_TYPE, &eckt, sizeof(eckt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_SENSITIVE, &no, sizeof(no) },
          { CKA_EXTRACTABLE, &yes, sizeof(yes) },
          { CKA_EC_PARAMS, rparams, sizeof(rparams) },
          { CKA_VALUE, scalar, sizeof(scalar) },
        };
        rv = f->C_CreateObject(sess, ptmpl, 7, &ecPriv);
        CHECKC(rv == CKR_OK && ecPriv != 0, "EC private import ok");
      }
      {
        CK_ATTRIBUTE ptmpl[] = {
          { CKA_CLASS, &pubcls, sizeof(pubcls) },
          { CKA_KEY_TYPE, &eckt, sizeof(eckt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_EC_PARAMS, rparams, sizeof(rparams) },
          { CKA_EC_POINT, point, sizeof(point) },
        };
        CK_ATTRIBUTE g[] = { { CKA_EC_POINT, NULL_PTR, 0 } };
        CK_BYTE got[67];
        rv = f->C_CreateObject(sess, ptmpl, 5, &ecPub);
        CHECKC(rv == CKR_OK && ecPub != 0, "EC public import ok");
        g[0].pValue = got;
        g[0].ulValueLen = sizeof(got);
        rv = f->C_GetAttributeValue(sess, ecPub, g, 1);
        CHECKC(rv == CKR_OK && g[0].ulValueLen == sizeof(point) &&
                   memcmp(got, point, sizeof(point)) == 0,
               "EC point reads back");
      }
      {
        CK_OBJECT_HANDLE bad = 0;
        CK_ATTRIBUTE btmpl[] = {
          { CKA_CLASS, &prvcls, sizeof(prvcls) },
          { CKA_KEY_TYPE, &rsakt, sizeof(rsakt) },
          { CKA_TOKEN, &no, sizeof(no) },
          { CKA_MODULUS, n, sizeof(n) },
          { CKA_PUBLIC_EXPONENT, e, 3 },
        };
        rv = f->C_CreateObject(sess, btmpl, 5, &bad);
        CHECKC(rv == CKR_TEMPLATE_INCOMPLETE && bad == 0,
               "partial RSA import incomplete");
      }
      rv = f->C_DestroyObject(sess, rsaPriv);
      CHECKC(rv == CKR_OK, "imported RSA priv destroyed");
      rv = f->C_DestroyObject(sess, rsaPub);
      CHECKC(rv == CKR_OK, "imported RSA pub destroyed");
      rv = f->C_DestroyObject(sess, ecPriv);
      CHECKC(rv == CKR_OK, "imported EC priv destroyed");
      rv = f->C_DestroyObject(sess, ecPub);
      CHECKC(rv == CKR_OK, "imported EC pub destroyed");
    }

    rv = f->C_DestroyObject(sess, dataObj);
    CHECKC(rv == CKR_OK, "DestroyObject ok");
    rv = f->C_DestroyObject(sess, dataObj);
    CHECKC(rv == CKR_OBJECT_HANDLE_INVALID, "double destroy invalid");
    {
      CK_BYTE buf[64];
      CK_ATTRIBUTE g[] = { { CKA_LABEL, buf, sizeof(buf) } };
      rv = f->C_GetAttributeValue(sess, dataObj, g, 1);
      CHECKC(rv == CKR_OBJECT_HANDLE_INVALID, "destroyed object unreadable");
    }
    rv = f->C_DestroyObject(sess, copyObj);
    CHECKC(rv == CKR_OK, "copy destroyed");
    rv = f->C_DestroyObject(sess, privObj);
    CHECKC(rv == CKR_OBJECT_HANDLE_INVALID,
           "hidden object undestroyable while logged out");
  }
  rv = f->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "CloseSession ok");
  rv = f->C_CloseSession(sess);
  CHECKC(rv == CKR_SESSION_HANDLE_INVALID, "double close invalid");

  /* ---- slot-event no-event + post-finalize state-first ---- */
  {
    CK_SLOT_ID sl = 0xDEADUL;
    rv = f->C_WaitForSlotEvent(CKF_DONT_BLOCK, &sl, NULL_PTR);
    CHECK(rv == CKR_NO_EVENT && sl == 0xDEADUL,
          "nonblocking wait reports NO_EVENT, slot untouched");
  }
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  rv = f->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "post-finalize OpenSession needs init (state first)");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("PASS: consumer_roundtrip (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
