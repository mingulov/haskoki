/* tests/c/layout_240.c - 2.40 independent layout/prototype probe.
 *
 * Compiled against the single pinned header ONLY
 * (spec/vendor), never against provider-generated
 * types: compile with -I spec/vendor -I cbits.
 * Part of scripts/test-c-abi.sh (acceptance A01/A02 source/ABI slice).
 *
 * Two layers:
 *   compile time - every scalar width, struct size/offset, constant value
 *     and function-pointer position/prototype is pinned with
 *     _Static_assert against hardcoded LP64 expectations. Any header or
 *     platform drift breaks the build (see --negative in test-c-abi.sh).
 *   run time - the probe loads the built libhaskoki.so given as argv[1]
 *     and checks the REAL legacy table: version {2,40}, all 68 entries
 *     non-NULL, plus spot behaviors through pinned offsets.
 */

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#include "pkcs11.h"
#include "abi_probe.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* ============ compile-time pins (LP64, Linux x86-64) ============ */

_Static_assert(sizeof(CK_ULONG) == 8, "CK_ULONG width");
/* NOTE: no CK_LONG assertion: the type is vestigial (defined but
 * never used by any struct or prototype in the standard) and the
 * pinned header omits it. All load-bearing scalar widths are
 * asserted below. */
_Static_assert(sizeof(CK_FLAGS) == 8, "CK_FLAGS width");
_Static_assert(sizeof(CK_RV) == 8, "CK_RV width");
_Static_assert(sizeof(CK_BYTE) == 1, "CK_BYTE width");
_Static_assert(sizeof(CK_BBOOL) == 1, "CK_BBOOL width");
_Static_assert(sizeof(CK_UTF8CHAR) == 1, "CK_UTF8CHAR width");
_Static_assert(sizeof(CK_SLOT_ID) == 8, "CK_SLOT_ID width");
_Static_assert(sizeof(CK_SESSION_HANDLE) == 8, "CK_SESSION_HANDLE width");
_Static_assert(sizeof(CK_OBJECT_HANDLE) == 8, "CK_OBJECT_HANDLE width");
_Static_assert(sizeof(CK_MECHANISM_TYPE) == 8, "CK_MECHANISM_TYPE width");
_Static_assert(sizeof(CK_USER_TYPE) == 8, "CK_USER_TYPE width");
_Static_assert(sizeof(CK_NOTIFICATION) == 8, "CK_NOTIFICATION width");
_Static_assert(_Alignof(CK_ULONG) == 8, "CK_ULONG alignment");

_Static_assert(sizeof(CK_VERSION) == 2, "CK_VERSION size");
_Static_assert(offsetof(CK_VERSION, major) == 0, "CK_VERSION.major");
_Static_assert(offsetof(CK_VERSION, minor) == 1, "CK_VERSION.minor");

_Static_assert(sizeof(CK_INFO) == 88, "CK_INFO size");
_Static_assert(offsetof(CK_INFO, cryptokiVersion) == 0, "CK_INFO.version");
_Static_assert(offsetof(CK_INFO, manufacturerID) == 2, "CK_INFO.manufacturer");
_Static_assert(offsetof(CK_INFO, flags) == 40, "CK_INFO.flags");
_Static_assert(offsetof(CK_INFO, libraryDescription) == 48, "CK_INFO.desc");
_Static_assert(offsetof(CK_INFO, libraryVersion) == 80, "CK_INFO.libversion");

_Static_assert(sizeof(CK_SLOT_INFO) == 112, "CK_SLOT_INFO size");
_Static_assert(offsetof(CK_SLOT_INFO, slotDescription) == 0, "slot.desc");
_Static_assert(offsetof(CK_SLOT_INFO, manufacturerID) == 64, "slot.manufacturer");
_Static_assert(offsetof(CK_SLOT_INFO, flags) == 96, "slot.flags");
_Static_assert(offsetof(CK_SLOT_INFO, hardwareVersion) == 104, "slot.hw");
_Static_assert(offsetof(CK_SLOT_INFO, firmwareVersion) == 106, "slot.fw");

_Static_assert(sizeof(CK_TOKEN_INFO) == 208, "CK_TOKEN_INFO size");
_Static_assert(offsetof(CK_TOKEN_INFO, label) == 0, "token.label");
_Static_assert(offsetof(CK_TOKEN_INFO, manufacturerID) == 32, "token.manufacturer");
_Static_assert(offsetof(CK_TOKEN_INFO, model) == 64, "token.model");
_Static_assert(offsetof(CK_TOKEN_INFO, serialNumber) == 80, "token.serial");
_Static_assert(offsetof(CK_TOKEN_INFO, flags) == 96, "token.flags");
_Static_assert(offsetof(CK_TOKEN_INFO, ulMaxSessionCount) == 104, "token.maxsess");
_Static_assert(offsetof(CK_TOKEN_INFO, ulSessionCount) == 112, "token.sess");
_Static_assert(offsetof(CK_TOKEN_INFO, ulMaxRwSessionCount) == 120, "token.maxrw");
_Static_assert(offsetof(CK_TOKEN_INFO, ulRwSessionCount) == 128, "token.rw");
_Static_assert(offsetof(CK_TOKEN_INFO, ulMaxPinLen) == 136, "token.maxpin");
_Static_assert(offsetof(CK_TOKEN_INFO, ulMinPinLen) == 144, "token.minpin");
_Static_assert(offsetof(CK_TOKEN_INFO, ulTotalPublicMemory) == 152, "token.totpub");
_Static_assert(offsetof(CK_TOKEN_INFO, ulFreePublicMemory) == 160, "token.freepub");
_Static_assert(offsetof(CK_TOKEN_INFO, ulTotalPrivateMemory) == 168, "token.totpriv");
_Static_assert(offsetof(CK_TOKEN_INFO, ulFreePrivateMemory) == 176, "token.freepriv");
_Static_assert(offsetof(CK_TOKEN_INFO, hardwareVersion) == 184, "token.hw");
_Static_assert(offsetof(CK_TOKEN_INFO, firmwareVersion) == 186, "token.fw");
_Static_assert(offsetof(CK_TOKEN_INFO, utcTime) == 188, "token.utc");

_Static_assert(sizeof(CK_SESSION_INFO) == 32, "CK_SESSION_INFO size");
_Static_assert(offsetof(CK_SESSION_INFO, slotID) == 0, "session.slot");
_Static_assert(offsetof(CK_SESSION_INFO, state) == 8, "session.state");
_Static_assert(offsetof(CK_SESSION_INFO, flags) == 16, "session.flags");
_Static_assert(offsetof(CK_SESSION_INFO, ulDeviceError) == 24, "session.err");

_Static_assert(sizeof(CK_ATTRIBUTE) == 24, "CK_ATTRIBUTE size");
_Static_assert(offsetof(CK_ATTRIBUTE, type) == 0, "attr.type");
_Static_assert(offsetof(CK_ATTRIBUTE, pValue) == 8, "attr.value");
_Static_assert(offsetof(CK_ATTRIBUTE, ulValueLen) == 16, "attr.len");

_Static_assert(sizeof(CK_MECHANISM) == 24, "CK_MECHANISM size");
_Static_assert(offsetof(CK_MECHANISM, mechanism) == 0, "mech.type");
_Static_assert(offsetof(CK_MECHANISM, pParameter) == 8, "mech.param");
_Static_assert(offsetof(CK_MECHANISM, ulParameterLen) == 16, "mech.paramlen");

_Static_assert(sizeof(CK_MECHANISM_INFO) == 24, "CK_MECHANISM_INFO size");
_Static_assert(offsetof(CK_MECHANISM_INFO, ulMinKeySize) == 0, "mechinfo.min");
_Static_assert(offsetof(CK_MECHANISM_INFO, ulMaxKeySize) == 8, "mechinfo.max");
_Static_assert(offsetof(CK_MECHANISM_INFO, flags) == 16, "mechinfo.flags");

_Static_assert(sizeof(CK_C_INITIALIZE_ARGS) == 48, "init-args size");
_Static_assert(offsetof(CK_C_INITIALIZE_ARGS, CreateMutex) == 0, "init.create");
_Static_assert(offsetof(CK_C_INITIALIZE_ARGS, DestroyMutex) == 8, "init.destroy");
_Static_assert(offsetof(CK_C_INITIALIZE_ARGS, LockMutex) == 16, "init.lock");
_Static_assert(offsetof(CK_C_INITIALIZE_ARGS, UnlockMutex) == 24, "init.unlock");
_Static_assert(offsetof(CK_C_INITIALIZE_ARGS, flags) == 32, "init.flags");
_Static_assert(offsetof(CK_C_INITIALIZE_ARGS, pReserved) == 40, "init.reserved");

/* Bedrock constants (values, not just presence). */
_Static_assert(CK_UNAVAILABLE_INFORMATION == ~0UL, "sentinel unavailable");
_Static_assert(CK_EFFECTIVELY_INFINITE == 0UL, "sentinel infinite");
_Static_assert(CK_INVALID_HANDLE == 0UL, "invalid handle");
_Static_assert(CKM_SHA256 == 0x250UL, "CKM_SHA256");
_Static_assert(CKR_OK == 0x0UL, "CKR_OK");
_Static_assert(CKR_GENERAL_ERROR == 0x5UL, "CKR_GENERAL_ERROR");
_Static_assert(CKR_ARGUMENTS_BAD == 0x7UL, "CKR_ARGUMENTS_BAD");
_Static_assert(CKR_NEED_TO_CREATE_THREADS == 0x9UL, "CKR_NEED_TO_CREATE_THREADS");
_Static_assert(CKR_FUNCTION_NOT_PARALLEL == 0x51UL, "CKR_FUNCTION_NOT_PARALLEL");
_Static_assert(CKR_FUNCTION_NOT_SUPPORTED == 0x54UL, "CKR_FUNCTION_NOT_SUPPORTED");
_Static_assert(CKR_BUFFER_TOO_SMALL == 0x150UL, "CKR_BUFFER_TOO_SMALL");
_Static_assert(CKR_CRYPTOKI_NOT_INITIALIZED == 0x190UL, "CKR_NOT_INITIALIZED");
_Static_assert(CKR_CRYPTOKI_ALREADY_INITIALIZED == 0x191UL, "CKR_ALREADY_INIT");
_Static_assert(CKF_LIBRARY_CANT_CREATE_OS_THREADS == 0x1UL, "CKF_CANT_THREADS");
_Static_assert(CKF_OS_LOCKING_OK == 0x2UL, "CKF_OS_LOCKING_OK");
_Static_assert(CKF_DIGEST == 0x400UL, "CKF_DIGEST");
/* 2.40 alias pair: alias, canonical and value must agree (A41). */
_Static_assert(CKA_SUB_PRIME_BITS == CKA_SUBPRIME_BITS, "2.40 alias");
_Static_assert(CKA_SUBPRIME_BITS == 0x134UL, "2.40 alias value");

/* Legacy table: 2 version bytes + 6 pad + 68 pointers. Each CHECK_FN pins
 * the hardcoded ordinal (byte offset) AND the exact prototype via the
 * pinned CK_C_* typedef. */
_Static_assert(sizeof(CK_FUNCTION_LIST) == 552, "CK_FUNCTION_LIST size");
#define CHECK_FN(listtype, idx, name) \
  _Static_assert(offsetof(struct listtype, name) == 8 + (idx)*8, \
                 "offset " #name); \
  _Static_assert(_Generic(((struct listtype *)0)->name, CK_##name: 1, \
                           default: 0), \
                 "prototype " #name)
CHECK_FN(CK_FUNCTION_LIST, 0, C_Initialize);
CHECK_FN(CK_FUNCTION_LIST, 1, C_Finalize);
CHECK_FN(CK_FUNCTION_LIST, 2, C_GetInfo);
CHECK_FN(CK_FUNCTION_LIST, 3, C_GetFunctionList);
CHECK_FN(CK_FUNCTION_LIST, 4, C_GetSlotList);
CHECK_FN(CK_FUNCTION_LIST, 5, C_GetSlotInfo);
CHECK_FN(CK_FUNCTION_LIST, 6, C_GetTokenInfo);
CHECK_FN(CK_FUNCTION_LIST, 7, C_GetMechanismList);
CHECK_FN(CK_FUNCTION_LIST, 8, C_GetMechanismInfo);
CHECK_FN(CK_FUNCTION_LIST, 9, C_InitToken);
CHECK_FN(CK_FUNCTION_LIST, 10, C_InitPIN);
CHECK_FN(CK_FUNCTION_LIST, 11, C_SetPIN);
CHECK_FN(CK_FUNCTION_LIST, 12, C_OpenSession);
CHECK_FN(CK_FUNCTION_LIST, 13, C_CloseSession);
CHECK_FN(CK_FUNCTION_LIST, 14, C_CloseAllSessions);
CHECK_FN(CK_FUNCTION_LIST, 15, C_GetSessionInfo);
CHECK_FN(CK_FUNCTION_LIST, 16, C_GetOperationState);
CHECK_FN(CK_FUNCTION_LIST, 17, C_SetOperationState);
CHECK_FN(CK_FUNCTION_LIST, 18, C_Login);
CHECK_FN(CK_FUNCTION_LIST, 19, C_Logout);
CHECK_FN(CK_FUNCTION_LIST, 20, C_CreateObject);
CHECK_FN(CK_FUNCTION_LIST, 21, C_CopyObject);
CHECK_FN(CK_FUNCTION_LIST, 22, C_DestroyObject);
CHECK_FN(CK_FUNCTION_LIST, 23, C_GetObjectSize);
CHECK_FN(CK_FUNCTION_LIST, 24, C_GetAttributeValue);
CHECK_FN(CK_FUNCTION_LIST, 25, C_SetAttributeValue);
CHECK_FN(CK_FUNCTION_LIST, 26, C_FindObjectsInit);
CHECK_FN(CK_FUNCTION_LIST, 27, C_FindObjects);
CHECK_FN(CK_FUNCTION_LIST, 28, C_FindObjectsFinal);
CHECK_FN(CK_FUNCTION_LIST, 29, C_EncryptInit);
CHECK_FN(CK_FUNCTION_LIST, 30, C_Encrypt);
CHECK_FN(CK_FUNCTION_LIST, 31, C_EncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST, 32, C_EncryptFinal);
CHECK_FN(CK_FUNCTION_LIST, 33, C_DecryptInit);
CHECK_FN(CK_FUNCTION_LIST, 34, C_Decrypt);
CHECK_FN(CK_FUNCTION_LIST, 35, C_DecryptUpdate);
CHECK_FN(CK_FUNCTION_LIST, 36, C_DecryptFinal);
CHECK_FN(CK_FUNCTION_LIST, 37, C_DigestInit);
CHECK_FN(CK_FUNCTION_LIST, 38, C_Digest);
CHECK_FN(CK_FUNCTION_LIST, 39, C_DigestUpdate);
CHECK_FN(CK_FUNCTION_LIST, 40, C_DigestKey);
CHECK_FN(CK_FUNCTION_LIST, 41, C_DigestFinal);
CHECK_FN(CK_FUNCTION_LIST, 42, C_SignInit);
CHECK_FN(CK_FUNCTION_LIST, 43, C_Sign);
CHECK_FN(CK_FUNCTION_LIST, 44, C_SignUpdate);
CHECK_FN(CK_FUNCTION_LIST, 45, C_SignFinal);
CHECK_FN(CK_FUNCTION_LIST, 46, C_SignRecoverInit);
CHECK_FN(CK_FUNCTION_LIST, 47, C_SignRecover);
CHECK_FN(CK_FUNCTION_LIST, 48, C_VerifyInit);
CHECK_FN(CK_FUNCTION_LIST, 49, C_Verify);
CHECK_FN(CK_FUNCTION_LIST, 50, C_VerifyUpdate);
CHECK_FN(CK_FUNCTION_LIST, 51, C_VerifyFinal);
CHECK_FN(CK_FUNCTION_LIST, 52, C_VerifyRecoverInit);
CHECK_FN(CK_FUNCTION_LIST, 53, C_VerifyRecover);
CHECK_FN(CK_FUNCTION_LIST, 54, C_DigestEncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST, 55, C_DecryptDigestUpdate);
CHECK_FN(CK_FUNCTION_LIST, 56, C_SignEncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST, 57, C_DecryptVerifyUpdate);
CHECK_FN(CK_FUNCTION_LIST, 58, C_GenerateKey);
CHECK_FN(CK_FUNCTION_LIST, 59, C_GenerateKeyPair);
CHECK_FN(CK_FUNCTION_LIST, 60, C_WrapKey);
CHECK_FN(CK_FUNCTION_LIST, 61, C_UnwrapKey);
CHECK_FN(CK_FUNCTION_LIST, 62, C_DeriveKey);
CHECK_FN(CK_FUNCTION_LIST, 63, C_SeedRandom);
CHECK_FN(CK_FUNCTION_LIST, 64, C_GenerateRandom);
CHECK_FN(CK_FUNCTION_LIST, 65, C_GetFunctionStatus);
CHECK_FN(CK_FUNCTION_LIST, 66, C_CancelFunction);
CHECK_FN(CK_FUNCTION_LIST, 67, C_WaitForSlotEvent);

/* ============ run-time checks against the loaded module ============ */

static int g_fails = 0;
static int g_checks = 0;

#define CHECK(cond, ...) \
  do { \
    g_checks++; \
    if (!(cond)) { \
      g_fails++; \
      printf("FAIL layout_240:%d: ", __LINE__); \
      printf(__VA_ARGS__); \
      printf("\n"); \
    } \
  } while (0)

static int slot_nonnull(const void *slot) {
  static const char zero[sizeof(void *)] = {0};
  return memcmp(slot, zero, sizeof(void *)) != 0;
}

int main(int argc, char **argv) {
  void *h;
  CK_C_GetFunctionList get_list;
  CK_FUNCTION_LIST_PTR p11 = NULL;
  CK_RV rv;
  size_t i;
  /* Canary-guarded C_GetInfo buffer: [canary][CK_INFO][canary]. */
  unsigned char guarded[16 + sizeof(CK_INFO) + 16];
  CK_INFO *info = (CK_INFO *)(guarded + 16);
  CK_ULONG count = 0;
  CK_ULONG outlen = 0;

  if (argc != 2) {
    printf("usage: layout_240 <libhaskoki.so>\n");
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(h != NULL, "dlopen %s: %s", argv[1], dlerror());
  if (h == NULL) {
    printf("layout_240: %d/%d checks passed\n", g_checks - g_fails, g_checks);
    return 1;
  }
  get_list = (CK_C_GetFunctionList)dlsym(h, "C_GetFunctionList");
  CHECK(get_list != NULL, "dlsym C_GetFunctionList");
  if (get_list == NULL) {
    dlclose(h);
    return 1;
  }

  /* Discovery before initialize (A01): valid table, {2,40} version. */
  rv = get_list(&p11);
  CHECK(rv == CKR_OK, "C_GetFunctionList rv=%lu", (unsigned long)rv);
  CHECK(p11 != NULL, "table pointer NULL");
  if (p11 == NULL) {
    dlclose(h);
    return 1;
  }
  CHECK(haskoki_version_eq(p11->version.major, p11->version.minor, 2, 40),
        "version %u.%u, want 2.40", p11->version.major, p11->version.minor);

  /* All 68 entries are real functions, never NULL (loader contract). The
   * +8 stride skips CK_VERSION+pad, verified field-by-field above. */
  for (i = 0; i < 68; i++) {
    const void *slot = (const char *)p11 + 8 + i * sizeof(void *);
    CHECK(slot_nonnull(slot), "legacy entry %lu is NULL", (unsigned long)i);
  }

  /* Spot behaviors through pinned offsets (pre-init). */
  haskoki_canary_fill(guarded, 16);
  haskoki_canary_fill(guarded + 16 + sizeof(CK_INFO), 16);
  memset(info, 0xCC, sizeof(*info));
  rv = p11->C_GetInfo(info);
  CHECK(rv == CKR_OK, "C_GetInfo rv=%lu", (unsigned long)rv);
  CHECK(haskoki_version_eq(info->cryptokiVersion.major,
                           info->cryptokiVersion.minor, 2, 40),
        "C_GetInfo version %u.%u", info->cryptokiVersion.major,
        info->cryptokiVersion.minor);
  CHECK(haskoki_canary_check(guarded, 16) &&
            haskoki_canary_check(guarded + 16 + sizeof(CK_INFO), 16),
        "C_GetInfo overran its buffer");
  rv = p11->C_GetSlotList(0, NULL, &count);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "C_GetSlotList pre-init rv=%lu",
        (unsigned long)rv);
  rv = p11->C_Digest(0, NULL, 0, NULL, &outlen);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "C_Digest pre-init rv=%lu",
        (unsigned long)rv);
  rv = p11->C_GetFunctionStatus(0);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "C_GetFunctionStatus pre-init rv=%lu",
        (unsigned long)rv);

  /* Init-phase pinned-offset spots: drive a live interval so routed
   * entries show distinct behaviors (sessions, slot/token info,
   * catalog, digest, login all route; only the legacy parallel pair
   * keeps its refusal). Any transposition between two live entries
   * surfaces as a wrong code here, closing the hand-mirror order gap
   * the non-NULL scan cannot see. */
  rv = p11->C_Initialize(NULL);
  CHECK(rv == CKR_OK, "C_Initialize rv=%lu", (unsigned long)rv);
  count = 0;
  rv = p11->C_GetSlotList(0, NULL, &count);
  CHECK(rv == CKR_OK && count == 1,
        "C_GetSlotList post-init rv=%lu n=%lu",
        (unsigned long)rv, (unsigned long)count);
  count = 0;
  rv = p11->C_GetMechanismList(0, NULL, &count);
  CHECK(rv == CKR_OK && count == 196,
        "C_GetMechanismList post-init rv=%lu n=%lu",
        (unsigned long)rv, (unsigned long)count);
  rv = p11->C_GetMechanismList(99, NULL, &count);
  CHECK(rv == CKR_SLOT_ID_INVALID, "C_GetMechanismList bad slot rv=%lu",
        (unsigned long)rv);
  {
    CK_MECHANISM_INFO minfo;
    CK_MECHANISM mech;
    CK_SLOT_INFO sinfo;
    CK_TOKEN_INFO tinfo;
    CK_SESSION_HANDLE sess = 0;
    CK_SESSION_INFO sessinfo;
    memset(&minfo, 0, sizeof(minfo));
    rv = p11->C_GetMechanismInfo(0, CKM_SHA256, &minfo);
    CHECK(rv == CKR_OK && (minfo.flags & CKF_DIGEST) != 0,
          "C_GetMechanismInfo rv=%lu flags=0x%lx",
          (unsigned long)rv, (unsigned long)minfo.flags);
    rv = p11->C_GetMechanismInfo(0, CKM_RSA_X9_31_KEY_PAIR_GEN, &minfo);
    CHECK(rv == CKR_MECHANISM_INVALID, "C_GetMechanismInfo bad mech rv=%lu",
          (unsigned long)rv);
    /* NULL out-param is ARGUMENTS_BAD; a real open yields a live RW
     * session in the public state. */
    rv = p11->C_OpenSession(0, 0, NULL, NULL, NULL);
    CHECK(rv == CKR_ARGUMENTS_BAD, "C_OpenSession NULL out rv=%lu",
          (unsigned long)rv);
    rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL, NULL, &sess);
    CHECK(rv == CKR_OK && sess != 0, "C_OpenSession RW rv=%lu sess=%lu",
          (unsigned long)rv, (unsigned long)sess);
    memset(&sessinfo, 0, sizeof(sessinfo));
    rv = p11->C_GetSessionInfo(sess, &sessinfo);
    CHECK(rv == CKR_OK && sessinfo.state == CKS_RW_PUBLIC_SESSION,
          "C_GetSessionInfo state=%lu", (unsigned long)sessinfo.state);
    /* Bad-handle digest update first (handle validation precedes
     * state), then the live-session update with no init. */
    rv = p11->C_DigestUpdate(0, NULL, 0);
    CHECK(rv == CKR_SESSION_HANDLE_INVALID, "C_DigestUpdate bad sess rv=%lu",
          (unsigned long)rv);
    rv = p11->C_DigestUpdate(sess, NULL, 0);
    CHECK(rv == CKR_OPERATION_NOT_INITIALIZED,
          "C_DigestUpdate no init rv=%lu", (unsigned long)rv);
    mech.mechanism = CKM_SHA256;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    rv = p11->C_DigestInit(sess, &mech);
    CHECK(rv == CKR_OK, "C_DigestInit rv=%lu", (unsigned long)rv);
    outlen = 0;
    rv = p11->C_Digest(sess, NULL, 0, NULL, &outlen);
    CHECK(rv == CKR_OK && outlen == 32,
          "C_Digest size query rv=%lu len=%lu",
          (unsigned long)rv, (unsigned long)outlen);
    /* Login routes: bad handle first, then engine refusals (bogus
     * type is stateless; wrong PIN proves credential checking). */
    rv = p11->C_Login(0, 0, NULL, 0);
    CHECK(rv == CKR_SESSION_HANDLE_INVALID, "C_Login bad sess rv=%lu",
          (unsigned long)rv);
    rv = p11->C_Login(sess, 99, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECK(rv == CKR_USER_TYPE_INVALID, "C_Login bogus type rv=%lu",
          (unsigned long)rv);
    rv = p11->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "9999", 4);
    CHECK(rv == CKR_PIN_INCORRECT, "C_Login wrong PIN rv=%lu",
          (unsigned long)rv);
    rv = p11->C_CloseSession(sess);
    CHECK(rv == CKR_OK, "C_CloseSession rv=%lu", (unsigned long)rv);
    /* Slot/token info route to the provisioned records; NULL
     * buffers are ARGUMENTS_BAD, bad slots rejected first. */
    rv = p11->C_GetSlotInfo(0, NULL);
    CHECK(rv == CKR_ARGUMENTS_BAD, "C_GetSlotInfo NULL rv=%lu",
          (unsigned long)rv);
    rv = p11->C_GetSlotInfo(99, NULL);
    CHECK(rv == CKR_SLOT_ID_INVALID, "C_GetSlotInfo bad slot rv=%lu",
          (unsigned long)rv);
    memset(&sinfo, 0, sizeof(sinfo));
    rv = p11->C_GetSlotInfo(0, &sinfo);
    CHECK(rv == CKR_OK && (sinfo.flags & CKF_TOKEN_PRESENT) != 0 &&
              memcmp(sinfo.slotDescription, "haskoki soft slot", 16) == 0,
          "C_GetSlotInfo routed rv=%lu", (unsigned long)rv);
    rv = p11->C_GetTokenInfo(0, NULL);
    CHECK(rv == CKR_ARGUMENTS_BAD, "C_GetTokenInfo NULL rv=%lu",
          (unsigned long)rv);
    rv = p11->C_GetTokenInfo(99, NULL);
    CHECK(rv == CKR_SLOT_ID_INVALID, "C_GetTokenInfo bad slot rv=%lu",
          (unsigned long)rv);
    memset(&tinfo, 0, sizeof(tinfo));
    rv = p11->C_GetTokenInfo(0, &tinfo);
    CHECK(rv == CKR_OK && memcmp(tinfo.label, "haskoki-demo", 12) == 0 &&
              (tinfo.flags & CKF_TOKEN_INITIALIZED) != 0 &&
              (tinfo.flags & CKF_LOGIN_REQUIRED) != 0,
          "C_GetTokenInfo routed rv=%lu", (unsigned long)rv);
  }
  rv = p11->C_GetFunctionStatus(0);
  CHECK(rv == CKR_FUNCTION_NOT_PARALLEL,
        "C_GetFunctionStatus post-init rv=%lu", (unsigned long)rv);
  rv = p11->C_CancelFunction(0);
  CHECK(rv == CKR_FUNCTION_NOT_PARALLEL, "C_CancelFunction stub rv=%lu",
        (unsigned long)rv);
  rv = p11->C_Finalize(NULL);
  CHECK(rv == CKR_OK, "C_Finalize rv=%lu", (unsigned long)rv);
  rv = p11->C_GetSlotList(0, NULL, &count);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "C_GetSlotList post-finalize rv=%lu", (unsigned long)rv);

  dlclose(h);
  printf("layout_240: %d/%d checks passed\n", g_checks - g_fails, g_checks);
  if (g_fails) {
    printf("FAIL: layout_240\n");
    return 1;
  }
  printf("PASS: layout_240\n");
  return 0;
}
