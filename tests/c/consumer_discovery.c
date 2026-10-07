/* tests/c/consumer_discovery.c — direct-load consumer: newer-API discovery.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module (or, in proxy topology, the pkcs11-proxy-ng
 * shim) and drives ONLY the standard 3.x discovery surface plus
 * metadata queries, through the pinned 3.2 headers:
 *   - C_GetInterfaceList / C_GetInterface per-interface discovery
 *     (3.2/3.1/3.0 + legacy C_GetFunctionList), callable pre-Initialize
 *   - versioned-table isolation (distinct instances, exact versions)
 *   - cross-table consistency (same bytes via legacy and 3.2 pointers)
 *   - mechanism/info queries (316 real-tested rows, info records,
 *     invalid codes)
 *   - real slot/token records (provisioned token) + session
 *     open/info/close/close-all flows
 *
 * Topology: HASKOKI_CONSUMER_TOPOLOGY=proxy selects proxy-mode
 * inventory expectations (the shim presents its own fixed catalog
 * [2.40, 3.0, 3.2] with a NULL-on-miss GetInterface contract; see
 * the 2026-09-21 proxy-parity session notes); anything else (including
 * unset) selects direct mode. Lines prefixed "invent:" carry
 * topology-specific assertions; all other check lines carry
 * topology-independent assertions over forwarded calls, and the
 * parity script diffs exactly those lines direct-vs-proxied.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_discovery <path-to-libhaskoki.so>
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

/* Topology-scoped check: prefixed so the parity script can exclude it
 * (the discovery inventory legitimately differs direct-vs-proxied). */
#define CHECKX(cond, ...)                                                  \
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

/* Hermetic config: real-crypto engine, trace off (no stray files),
 * memory storage. Written to a temp file; HASKOKI_CONFIG points at it
 * before the module resolves its config at C_Initialize. In proxy
 * topology the server side carries the backend config; this local
 * config is harmless (the shim ignores it). */
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
  CK_C_GetInterfaceList pGetInterfaceList;
  CK_C_GetInterface pGetInterface;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_INTERFACE ifaces[8];
  CK_ULONG count = 0;
  CK_INTERFACE_PTR p32 = NULL_PTR, p31 = NULL_PTR, p30 = NULL_PTR;
  CK_FUNCTION_LIST_3_2_PTR tbl32 = NULL_PTR;
  CK_FUNCTION_LIST_3_0_PTR tbl31 = NULL_PTR, tbl30 = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  CK_INFO infoL, info3;
  CK_SLOT_ID slotsL[16], slots3[16];
  CK_ULONG nL = 16, n3 = 16;
  CK_MECHANISM_TYPE mechs[316];
  CK_MECHANISM_TYPE mechsL[316];
  CK_ULONG nmech = 316;
  CK_ULONG nmechL = 316;
  CK_MECHANISM_INFO mi;
  CK_SLOT_INFO si;
  CK_TOKEN_INFO ti;
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

  /* ---- discovery before Initialize (no Haskell entry needed) ---- */
  /* Direct catalog is the backend's own 3 (3.2/3.1/3.0). Proxied,
   * pkcs11-proxy-ng >= 0.2.1 merges the backend-published
   * interfaces into the seeded shim list, so the live catalog is
   * 4 (2.40/3.0/3.1/3.2) with a functional 3.1. */
  count = 0;
  rv = pGetInterfaceList(NULL_PTR, &count);
  CHECK(rv == CKR_OK && count == (isProxy ? 4 : 3),
        "interface count query matches catalog (3 direct / 4 proxy)");
  count = 2;
  rv = pGetInterfaceList(ifaces, &count);
  CHECK(rv == CKR_BUFFER_TOO_SMALL && count == (isProxy ? 4 : 3),
        "short interface buffer reports catalog size");
  count = 8;
  rv = pGetInterfaceList(ifaces, &count);
  CHECK(rv == CKR_OK && count == (isProxy ? 4 : 3),
        "interface list fetches catalog");
  CHECK(strcmp((const char *)ifaces[0].pInterfaceName, "PKCS 11") == 0 &&
            strcmp((const char *)ifaces[1].pInterfaceName, "PKCS 11") == 0 &&
            strcmp((const char *)ifaces[2].pInterfaceName, "PKCS 11") == 0,
        "all interfaces named 'PKCS 11'");
  {
    CK_VERSION *v0 = (CK_VERSION *)ifaces[0].pFunctionList;
    CK_VERSION *v1 = (CK_VERSION *)ifaces[1].pFunctionList;
    CK_VERSION *v2 = (CK_VERSION *)ifaces[2].pFunctionList;
    if (!isProxy) {
      CHECKX(v0->major == 3 && v0->minor == 2, "iface[0] is 3.2");
      CHECKX(v1->major == 3 && v1->minor == 1, "iface[1] is 3.1");
      CHECKX(v2->major == 3 && v2->minor == 0, "iface[2] is 3.0");
    } else {
      /* Merged catalog: seeded 2.40/3.0/3.2 plus the backend's
       * published 3.1, sorted into place. */
      CK_VERSION *v3 = (CK_VERSION *)ifaces[3].pFunctionList;
      CHECKX(v0->major == 2 && v0->minor == 40, "iface[0] is 2.40");
      CHECKX(v1->major == 3 && v1->minor == 0, "iface[1] is 3.0");
      CHECKX(v2->major == 3 && v2->minor == 1, "iface[2] is 3.1");
      CHECKX(v3->major == 3 && v3->minor == 2, "iface[3] is 3.2");
      CHECKX(strcmp((const char *)ifaces[3].pInterfaceName, "PKCS 11") == 0,
             "iface[3] named 'PKCS 11'");
    }
  }
  CHECK(ifaces[0].flags == 0 && ifaces[1].flags == 0 && ifaces[2].flags == 0,
        "no interface claims fork-safe");
  if (isProxy) {
    CHECKX(ifaces[3].flags == 0, "iface[3] claims no fork-safe");
  }

  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p32, 0);
  CHECK(rv == CKR_OK && p32 != NULL_PTR, "GetInterface selects 3.2");
  v.minor = 1;
  p31 = NULL_PTR;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p31, 0);
  if (!isProxy) {
    CHECKX(rv == CKR_OK && p31 != NULL_PTR, "GetInterface selects 3.1");
  } else {
    /* Backend-published 3.1 is merged into the live catalog and
     * functional (Initialize/slot-list/finalize verified). */
    CHECKX(rv == CKR_OK && p31 != NULL_PTR,
           "GetInterface selects proxied 3.1");
  }
  v.minor = 0;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p30, 0);
  CHECK(rv == CKR_OK && p30 != NULL_PTR, "GetInterface selects 3.0");
  {
    CK_INTERFACE_PTR pAny = NULL_PTR;
    rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", NULL_PTR, &pAny, 0);
    CHECK(rv == CKR_OK && pAny == p32, "NULL version selects newest (3.2)");
    pAny = NULL_PTR;
    v.major = 3;
    v.minor = 0;
    rv = pGetInterface(NULL_PTR, &v, &pAny, 0);
    CHECK(rv == CKR_OK && pAny == p30, "NULL name + 3.0 selects 3.0");
    pAny = (CK_INTERFACE_PTR)0x1;
    rv = pGetInterface((CK_UTF8CHAR_PTR) "NOPE", NULL_PTR, &pAny, 0);
    if (!isProxy) {
      CHECKX(rv == CKR_ARGUMENTS_BAD, "unknown name rejected");
    } else {
      CHECKX(rv == CKR_OK && pAny == NULL_PTR,
             "unknown name misses NULL (shim contract)");
    }
    v.major = 9;
    v.minor = 9;
    pAny = (CK_INTERFACE_PTR)0x1;
    rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &pAny, 0);
    if (!isProxy) {
      CHECKX(rv == CKR_ARGUMENTS_BAD, "unknown version rejected");
    } else {
      CHECKX(rv == CKR_OK && pAny == NULL_PTR,
             "unknown version misses NULL (shim contract)");
    }
    v.major = 3;
    v.minor = 2;
    rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, NULL_PTR, 0);
    CHECK(rv == CKR_ARGUMENTS_BAD, "NULL out-pointer rejected");
  }

  /* ---- versioned-table isolation (guarded: never deref a miss) ---- */
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
  if (!isProxy) {
    CHECKX(tbl31 != NULL_PTR, "3.1 table selected");
    CHECKX((void *)tbl32 != (void *)tbl31 && (void *)tbl32 != (void *)tbl30 &&
               (void *)tbl31 != (void *)tbl30 &&
               (void *)legacy != (void *)tbl32 &&
               (void *)legacy != (void *)tbl31 &&
               (void *)legacy != (void *)tbl30,
           "legacy + 3.x table instances all distinct");
    CHECKX(tbl32->version.major == 3 && tbl32->version.minor == 2 &&
               tbl31->version.major == 3 && tbl31->version.minor == 1 &&
               tbl30->version.major == 3 && tbl30->version.minor == 0,
           "3.x table versions exact");
  } else {
    CHECKX(tbl31 != NULL_PTR, "shim 3.1 table selected");
    CHECKX((void *)tbl32 != (void *)tbl31 &&
               (void *)tbl32 != (void *)tbl30 &&
               (void *)tbl31 != (void *)tbl30 &&
               (void *)legacy != (void *)tbl32 &&
               (void *)legacy != (void *)tbl31 &&
               (void *)legacy != (void *)tbl30,
           "legacy + shim 3.2/3.1/3.0 instances distinct");
    CHECKX(tbl32->version.major == 3 && tbl32->version.minor == 2 &&
               tbl31->version.major == 3 && tbl31->version.minor == 1 &&
               tbl30->version.major == 3 && tbl30->version.minor == 0,
           "shim 3.2/3.1/3.0 table versions exact");
  }
  if (!tbl32 || !tbl30) {
    printf("FAIL: required tables missing; aborting forwarded section\n");
    return 1;
  }

  /* ---- Initialize through the 3.2 table (newer-API path) ---- */
  rv = tbl32->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "3.2 C_Initialize ok");

  /* ---- cross-table consistency: same bytes, legacy vs 3.2 ---- */
  memset(&infoL, 0, sizeof(infoL));
  memset(&info3, 0, sizeof(info3));
  rv = legacy->C_GetInfo(&infoL);
  CHECK(rv == CKR_OK, "legacy C_GetInfo ok");
  rv = tbl32->C_GetInfo(&info3);
  CHECK(rv == CKR_OK, "3.2 C_GetInfo ok");
  CHECK(memcmp(&infoL, &info3, sizeof(CK_INFO)) == 0,
        "GetInfo identical via legacy and 3.2");
  CHECK(info3.cryptokiVersion.major == 2 && info3.cryptokiVersion.minor == 40,
        "cryptoki version 2.40");
  CHECK(info3.libraryVersion.major == 0 && info3.libraryVersion.minor == 3,
        "library version 0.3");
  CHECK(memcmp(info3.manufacturerID, "                                ", 32) !=
            0 &&
            memcmp(info3.libraryDescription,
                   "                                ", 32) != 0,
        "manufacturer/description non-blank");

  nL = 16;
  rv = legacy->C_GetSlotList(0, slotsL, &nL);
  CHECK(rv == CKR_OK && nL == 1, "legacy slot list has 1 slot");
  n3 = 16;
  rv = tbl32->C_GetSlotList(0, slots3, &n3);
  CHECK(rv == CKR_OK && n3 == 1 && slots3[0] == slotsL[0],
        "3.2 slot list matches legacy");
  {
    CK_ULONG nq = 0;
    rv = tbl32->C_GetSlotList(0, NULL_PTR, &nq);
    CHECK(rv == CKR_OK && nq == 1, "slot list size query reports 1");
  }
  n3 = 16;
  rv = tbl32->C_GetSlotList(1, slots3, &n3);
  CHECK(rv == CKR_OK && n3 == 1 && slots3[0] == slotsL[0],
        "token-present list holds the provisioned slot");

  /* ---- table skew: the 68 legacy entries re-home by
   * name, so legacy and 3.2 pointers run identical code over one
   * shared instance. Direct-only pointer identity plus both-
   * topology behavior parity. */
  if (!isProxy) {
    CHECKX((void *)legacy->C_DigestInit == (void *)tbl32->C_DigestInit &&
               (void *)legacy->C_Digest == (void *)tbl32->C_Digest &&
               (void *)legacy->C_DigestUpdate == (void *)tbl32->C_DigestUpdate &&
               (void *)legacy->C_DigestFinal == (void *)tbl32->C_DigestFinal &&
               (void *)legacy->C_SignInit == (void *)tbl32->C_SignInit &&
               (void *)legacy->C_Sign == (void *)tbl32->C_Sign &&
               (void *)legacy->C_Verify == (void *)tbl32->C_Verify &&
               (void *)legacy->C_EncryptInit == (void *)tbl32->C_EncryptInit &&
               (void *)legacy->C_Encrypt == (void *)tbl32->C_Encrypt &&
               (void *)legacy->C_Decrypt == (void *)tbl32->C_Decrypt &&
               (void *)legacy->C_GenerateKey == (void *)tbl32->C_GenerateKey &&
               (void *)legacy->C_GenerateKeyPair ==
                   (void *)tbl32->C_GenerateKeyPair &&
               (void *)legacy->C_WrapKey == (void *)tbl32->C_WrapKey &&
               (void *)legacy->C_UnwrapKey == (void *)tbl32->C_UnwrapKey &&
               (void *)legacy->C_DeriveKey == (void *)tbl32->C_DeriveKey &&
               (void *)legacy->C_CreateObject == (void *)tbl32->C_CreateObject &&
               (void *)legacy->C_Login == (void *)tbl32->C_Login &&
               (void *)legacy->C_GenerateRandom ==
                   (void *)tbl32->C_GenerateRandom &&
               (void *)legacy->C_SeedRandom ==
                   (void *)tbl32->C_SeedRandom,
           "routed entries share code pointers legacy/3.2");
  }
  nmechL = 316;
  rv = legacy->C_GetMechanismList(slotsL[0], mechsL, &nmechL);
  CHECK(rv == CKR_OK && nmechL == 316, "legacy mechanism list has 316 rows");
  {
    CK_ULONG nq = 316;
    rv = tbl32->C_GetMechanismList(slotsL[0], mechs, &nq);
    CHECK(rv == CKR_OK && nq == nmechL &&
              memcmp(mechs, mechsL, nq * sizeof(CK_MECHANISM_TYPE)) == 0,
          "mechanism list identical legacy/3.2");
  }
  {
    CK_SESSION_HANDLE xsess = 0;
    CK_SESSION_INFO siL, si3;
    CK_MECHANISM dm;
    CK_BYTE outL[64], out3[64];
    CK_ULONG lenL = sizeof(outL), len3 = sizeof(out3);
    dm.mechanism = CKM_SHA256;
    dm.pParameter = NULL_PTR;
    dm.ulParameterLen = 0;
    rv = legacy->C_OpenSession(slotsL[0],
                               CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR,
                               NULL_PTR, &xsess);
    CHECK(rv == CKR_OK && xsess != 0, "legacy session opens");
    rv = legacy->C_GetSessionInfo(xsess, &siL);
    CHECK(rv == CKR_OK, "legacy session info ok");
    rv = tbl32->C_GetSessionInfo(xsess, &si3);
    CHECK(rv == CKR_OK && memcmp(&siL, &si3, sizeof(siL)) == 0,
          "session info identical legacy/3.2");
    rv = legacy->C_DigestInit(xsess, &dm);
    CHECK(rv == CKR_OK, "legacy digest init ok");
    rv = legacy->C_Digest(xsess, (CK_BYTE_PTR) "abc", 3, outL, &lenL);
    CHECK(rv == CKR_OK && lenL == 32, "legacy digest yields 32 bytes");
    rv = tbl32->C_DigestInit(xsess, &dm);
    CHECK(rv == CKR_OK, "3.2 digest init ok on legacy session");
    rv = tbl32->C_Digest(xsess, (CK_BYTE_PTR) "abc", 3, out3, &len3);
    CHECK(rv == CKR_OK && len3 == 32 && memcmp(outL, out3, 32) == 0,
          "digest bytes identical legacy/3.2");
    /* ---- SeedRandom is live on every table (the 3.x
     * tables re-home the legacy entry by name, so one flip routes
     * all four; 3.1 exists in direct mode only) ---- */
    {
      CK_BYTE seed[16];
      memset(seed, 0x5A, sizeof(seed));
      rv = legacy->C_SeedRandom(xsess, seed, sizeof(seed));
      CHECK(rv == CKR_OK, "legacy SeedRandom ok");
      rv = tbl32->C_SeedRandom(xsess, seed, sizeof(seed));
      CHECK(rv == CKR_OK, "3.2 SeedRandom ok");
      rv = tbl30->C_SeedRandom(xsess, seed, sizeof(seed));
      CHECK(rv == CKR_OK, "3.0 SeedRandom ok");
      if (tbl31 != NULL_PTR) {
        rv = tbl31->C_SeedRandom(xsess, seed, sizeof(seed));
        CHECKX(rv == CKR_OK, "3.1 SeedRandom ok");
      }
    }
    rv = legacy->C_CloseSession(xsess);
    CHECK(rv == CKR_OK, "legacy session closes");
  }

  /* ---- mechanism/info queries ---- */
  nmech = 316;
  rv = tbl32->C_GetMechanismList(slotsL[0], mechs, &nmech);
  CHECK(rv == CKR_OK && nmech == 316, "mechanism list has 316 rows");
  {
    int has256 = 0, hasPad = 0, hasEC = 0, hasAESkg = 0, hasHOTPkg = 0;
    int hasKEM = 0, hasKEMkg = 0, hasMontgomery = 0, hasB2s = 0;
    int ascending = 1;
    CK_ULONG i = 0;
    for (i = 0; i < nmech; i++) {
      if (mechs[i] == CKM_SHA256) {
        has256 = 1;
      }
      if (mechs[i] == CKM_AES_CBC_PAD) {
        hasPad = 1;
      }
      if (mechs[i] == CKM_EC_KEY_PAIR_GEN) {
        hasEC = 1;
      }
      if (mechs[i] == CKM_AES_KEY_GEN) {
        hasAESkg = 1;
      }
      if (mechs[i] == CKM_HOTP_KEY_GEN) {
        hasHOTPkg = 1;
      }
      if (mechs[i] == CKM_ML_KEM) {
        hasKEM = 1;
      }
      if (mechs[i] == CKM_ML_KEM_KEY_PAIR_GEN) {
        hasKEMkg = 1;
      }
      if (mechs[i] == CKM_EC_MONTGOMERY_KEY_PAIR_GEN) {
        hasMontgomery = 1;
      }
      if (mechs[i] == CKM_BLAKE2B_160) {
        hasB2s = 1;
      }
      if (i > 0 && mechs[i] <= mechs[i - 1]) {
        ascending = 0;
      }
    }
    CHECK(has256 && hasPad && hasEC && hasAESkg && hasHOTPkg && hasMontgomery && hasB2s,
          "digest/cipher/keygen members present");
    CHECK(hasKEM && hasKEMkg, "KEM members present");
    CHECK(ascending, "mechanism list ascends");
  }
  {
    CK_ULONG nq = 0;
    rv = tbl32->C_GetMechanismList(slotsL[0], NULL_PTR, &nq);
    CHECK(rv == CKR_OK && nq == 316, "mechanism size query reports 316");
  }
  nmech = 3;
  rv = tbl32->C_GetMechanismList(slotsL[0], mechs, &nmech);
  CHECK(rv == CKR_BUFFER_TOO_SMALL && nmech == 316,
        "short mechanism buffer reports 316");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_SHA256, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 0 && mi.ulMaxKeySize == 0 &&
            mi.flags == CKF_DIGEST,
        "SHA256 info: digest-only, no key sizes");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_AES_KEY_GEN, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 128 && mi.ulMaxKeySize == 256 &&
            mi.flags == CKF_GENERATE,
        "AES_KEY_GEN info: generate-only, 128-256 bits");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_AES_CBC_PAD, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 16 && mi.ulMaxKeySize == 32 &&
            mi.flags == (CKF_ENCRYPT | CKF_DECRYPT | CKF_MESSAGE_ENCRYPT |
                         CKF_MESSAGE_DECRYPT),
        "AES_CBC_PAD info: 16..32, encrypt/decrypt, message encrypt/decrypt");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_RSA_PKCS_KEY_PAIR_GEN, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 0 && mi.ulMaxKeySize == 0 &&
            mi.flags == CKF_GENERATE_KEY_PAIR,
        "RSA_KEY_PAIR_GEN info: generate-pair-only, 0/0 bounds");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_ML_KEM_KEY_PAIR_GEN, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 800 && mi.ulMaxKeySize == 1568 &&
            mi.flags == CKF_GENERATE_KEY_PAIR,
        "ML_KEM_KEY_PAIR_GEN info: generate-pair-only, 800..1568");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_ML_KEM, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 800 && mi.ulMaxKeySize == 1568 &&
            mi.flags == (CKF_ENCAPSULATE | CKF_DECAPSULATE),
        "ML_KEM info: 800..1568, encapsulate/decapsulate");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_AES_GCM, &mi);
  /* F-9: GCM message flags withdrawn (FINAL-101); classic encrypt/decrypt stay. */
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 16 && mi.ulMaxKeySize == 32 &&
            mi.flags == (CKF_ENCRYPT | CKF_DECRYPT),
        "AES_GCM info: 16..32, encrypt/decrypt, no message flags, no wrap flags");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_DES_CBC, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 8 && mi.ulMaxKeySize == 8 &&
            mi.flags == (CKF_ENCRYPT | CKF_DECRYPT | CKF_MESSAGE_ENCRYPT |
                         CKF_MESSAGE_DECRYPT),
        "DES_CBC info: 8/8, encrypt/decrypt, message encrypt/decrypt");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_RC2_CBC, &mi);
  CHECK(rv == CKR_OK && mi.ulMinKeySize == 1 && mi.ulMaxKeySize == 128 &&
            mi.flags == (CKF_ENCRYPT | CKF_DECRYPT | CKF_MESSAGE_ENCRYPT |
                         CKF_MESSAGE_DECRYPT),
        "RC2_CBC info: 1..128, encrypt/decrypt, message encrypt/decrypt");
  rv = tbl32->C_GetMechanismInfo(slotsL[0], CKM_RSA_X9_31_KEY_PAIR_GEN, &mi);
  CHECK(rv == CKR_MECHANISM_INVALID, "unlisted mechanism info rejected");
  rv = tbl32->C_GetMechanismInfo(999991UL, CKM_SHA256, &mi);
  CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot mechanism info rejected");

  /* ---- real slot/token records (provisioned token) ---- */
  rv = tbl32->C_GetSlotInfo(slotsL[0], &si);
  CHECK(rv == CKR_OK && (si.flags & CKF_TOKEN_PRESENT) != 0 &&
            memcmp(si.slotDescription, "haskoki soft slot", 16) == 0 &&
            memcmp(si.manufacturerID, "haskoki contributors", 20) == 0,
        "GetSlotInfo: token present, pinned strings");
  rv = tbl32->C_GetSlotInfo(999991UL, &si);
  CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot slot-info rejected");
  rv = tbl32->C_GetTokenInfo(slotsL[0], &ti);
  CHECK(rv == CKR_OK && memcmp(ti.label, "haskoki-demo", 12) == 0 &&
            memcmp(ti.manufacturerID, "haskoki contributors", 20) == 0 &&
            memcmp(ti.model, "soft-token", 10) == 0 &&
            (ti.flags & CKF_TOKEN_INITIALIZED) != 0 &&
            (ti.flags & CKF_USER_PIN_INITIALIZED) != 0 &&
            (ti.flags & CKF_LOGIN_REQUIRED) != 0,
        "GetTokenInfo: pinned label/flags");
  rv = tbl32->C_GetTokenInfo(999991UL, &ti);
  CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot token-info rejected");

  /* ---- sessions: open/info/close/close-all ---- */
  {
    CK_SESSION_HANDLE sess = 0, ro1 = 0, ro2 = 0;
    CK_SESSION_INFO sinfo;
    rv = tbl32->C_OpenSession(slotsL[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
    CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok");
    rv = tbl32->C_GetSessionInfo(sess, &sinfo);
    CHECK(rv == CKR_OK && sinfo.slotID == slotsL[0] &&
              sinfo.state == CKS_RW_PUBLIC_SESSION &&
              (sinfo.flags & CKF_RW_SESSION) != 0 &&
              (sinfo.flags & CKF_SERIAL_SESSION) != 0 &&
              sinfo.ulDeviceError == 0,
        "GetSessionInfo RW public");
    rv = tbl32->C_CloseSession(sess);
    CHECK(rv == CKR_OK, "CloseSession ok");
    rv = tbl32->C_CloseSession(sess);
    CHECK(rv == CKR_SESSION_HANDLE_INVALID, "double close invalid");
    rv = tbl32->C_GetSessionInfo(sess, &sinfo);
    CHECK(rv == CKR_SESSION_HANDLE_INVALID, "closed session info invalid");
    rv = tbl32->C_OpenSession(slotsL[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                            &ro1);
    CHECK(rv == CKR_OK && ro1 != 0, "OpenSession RO ok");
    rv = tbl32->C_GetSessionInfo(ro1, &sinfo);
    CHECK(rv == CKR_OK && sinfo.state == CKS_RO_PUBLIC_SESSION &&
              (sinfo.flags & CKF_RW_SESSION) == 0,
        "GetSessionInfo RO public");
    rv = tbl32->C_OpenSession(slotsL[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                            &ro2);
    CHECK(rv == CKR_OK && ro2 != 0 && ro2 != ro1, "second RO distinct");
    rv = tbl32->C_CloseAllSessions(slotsL[0]);
    CHECK(rv == CKR_OK, "CloseAllSessions ok");
    rv = tbl32->C_GetSessionInfo(ro1, &sinfo);
    CHECK(rv == CKR_SESSION_HANDLE_INVALID, "close-all kills first");
    rv = tbl32->C_GetSessionInfo(ro2, &sinfo);
    CHECK(rv == CKR_SESSION_HANDLE_INVALID, "close-all kills second");
    rv = tbl32->C_OpenSession(999991UL, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                            &sess);
    CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot open rejected");
    rv = tbl32->C_OpenSession(slotsL[0], 0, NULL_PTR, NULL_PTR, &sess);
    CHECK(rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED, "parallel open refused");
    rv = tbl32->C_CloseAllSessions(999991UL);
    CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot close-all rejected");
  }

  /* ---- lifecycle: finalize, post-finalize, re-init ---- */
  rv = tbl32->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "3.2 C_Finalize ok");
  n3 = 16;
  rv = tbl32->C_GetSlotList(0, slots3, &n3);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "post-finalize slot list needs init");
  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "re-initialize ok");
  rv = legacy->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "second finalize ok");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("PASS: consumer_discovery (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
