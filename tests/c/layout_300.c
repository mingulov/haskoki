/* tests/c/layout_300.c - 3.0 independent layout/prototype probe.
 *
 * Compiled against the single pinned header ONLY
 * (spec/vendor/pkcs11.h - never provider-generated types): compile
 * with -I spec/vendor -I cbits -DPKCS11_DEPRECATED=1 (the flag exposes
 * the DSA typo spelling asserted below).
 * Part of scripts/test-c-abi.sh (acceptance A01/A02 source/ABI slice).
 *
 * Compile time: scalar widths, struct sizes/offsets, constant values and
 * all 92 CK_FUNCTION_LIST_3_0 positions/prototypes are pinned with
 * _Static_assert. Run time: the probe loads libhaskoki.so (argv[1]),
 * selects interface ("PKCS 11", {3,0}) and checks the REAL 3.0 table.
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

_Static_assert(sizeof(CK_INTERFACE) == 24, "CK_INTERFACE size");
_Static_assert(offsetof(CK_INTERFACE, pInterfaceName) == 0, "iface.name");
_Static_assert(offsetof(CK_INTERFACE, pFunctionList) == 8, "iface.list");
_Static_assert(offsetof(CK_INTERFACE, flags) == 16, "iface.flags");

/* Bedrock constants. */
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
_Static_assert(CKF_INTERFACE_FORK_SAFE == 0x1UL, "CKF_INTERFACE_FORK_SAFE");
_Static_assert(CKF_END_OF_MESSAGE == 0x1UL, "CKF_END_OF_MESSAGE");
/* Corrected-family alias pairs: typo/canonical spellings share one value. */
_Static_assert(CKM_SHA3_256_KEY_DERIVE == CKM_SHA3_256_KEY_DERIVATION, "3.0 alias sha3");
_Static_assert(CKM_SHA3_256_KEY_DERIVATION == 0x397UL, "3.0 alias sha3 value");
_Static_assert(CKF_MULTI_MESSGE == CKF_MULTI_MESSAGE, "3.0 alias multi");
_Static_assert(CKF_MULTI_MESSAGE == 0x20UL, "3.0 alias multi value");
_Static_assert(CKM_DSA_PROBABLISTIC_PARAMETER_GEN ==
                  CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
              "3.0 alias dsa");
_Static_assert(CKM_DSA_PROBABILISTIC_PARAMETER_GEN == 0x2003UL, "3.0 alias dsa value");

/* Legacy layout inside the 3.0 headers is still the 68-entry shape. */
_Static_assert(sizeof(CK_FUNCTION_LIST) == 552, "legacy list size in 3.0 hdrs");

/* 3.0 table: 2 version bytes + 6 pad + 92 pointers. */
_Static_assert(sizeof(CK_FUNCTION_LIST_3_0) == 744, "CK_FUNCTION_LIST_3_0 size");
#define CHECK_FN(listtype, idx, name) \
  _Static_assert(offsetof(struct listtype, name) == 8 + (idx)*8, \
                 "offset " #name); \
  _Static_assert(_Generic(((struct listtype *)0)->name, CK_##name: 1, \
                           default: 0), \
                 "prototype " #name)
CHECK_FN(CK_FUNCTION_LIST_3_0, 0, C_Initialize);
CHECK_FN(CK_FUNCTION_LIST_3_0, 1, C_Finalize);
CHECK_FN(CK_FUNCTION_LIST_3_0, 2, C_GetInfo);
CHECK_FN(CK_FUNCTION_LIST_3_0, 3, C_GetFunctionList);
CHECK_FN(CK_FUNCTION_LIST_3_0, 4, C_GetSlotList);
CHECK_FN(CK_FUNCTION_LIST_3_0, 5, C_GetSlotInfo);
CHECK_FN(CK_FUNCTION_LIST_3_0, 6, C_GetTokenInfo);
CHECK_FN(CK_FUNCTION_LIST_3_0, 7, C_GetMechanismList);
CHECK_FN(CK_FUNCTION_LIST_3_0, 8, C_GetMechanismInfo);
CHECK_FN(CK_FUNCTION_LIST_3_0, 9, C_InitToken);
CHECK_FN(CK_FUNCTION_LIST_3_0, 10, C_InitPIN);
CHECK_FN(CK_FUNCTION_LIST_3_0, 11, C_SetPIN);
CHECK_FN(CK_FUNCTION_LIST_3_0, 12, C_OpenSession);
CHECK_FN(CK_FUNCTION_LIST_3_0, 13, C_CloseSession);
CHECK_FN(CK_FUNCTION_LIST_3_0, 14, C_CloseAllSessions);
CHECK_FN(CK_FUNCTION_LIST_3_0, 15, C_GetSessionInfo);
CHECK_FN(CK_FUNCTION_LIST_3_0, 16, C_GetOperationState);
CHECK_FN(CK_FUNCTION_LIST_3_0, 17, C_SetOperationState);
CHECK_FN(CK_FUNCTION_LIST_3_0, 18, C_Login);
CHECK_FN(CK_FUNCTION_LIST_3_0, 19, C_Logout);
CHECK_FN(CK_FUNCTION_LIST_3_0, 20, C_CreateObject);
CHECK_FN(CK_FUNCTION_LIST_3_0, 21, C_CopyObject);
CHECK_FN(CK_FUNCTION_LIST_3_0, 22, C_DestroyObject);
CHECK_FN(CK_FUNCTION_LIST_3_0, 23, C_GetObjectSize);
CHECK_FN(CK_FUNCTION_LIST_3_0, 24, C_GetAttributeValue);
CHECK_FN(CK_FUNCTION_LIST_3_0, 25, C_SetAttributeValue);
CHECK_FN(CK_FUNCTION_LIST_3_0, 26, C_FindObjectsInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 27, C_FindObjects);
CHECK_FN(CK_FUNCTION_LIST_3_0, 28, C_FindObjectsFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 29, C_EncryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 30, C_Encrypt);
CHECK_FN(CK_FUNCTION_LIST_3_0, 31, C_EncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 32, C_EncryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 33, C_DecryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 34, C_Decrypt);
CHECK_FN(CK_FUNCTION_LIST_3_0, 35, C_DecryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 36, C_DecryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 37, C_DigestInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 38, C_Digest);
CHECK_FN(CK_FUNCTION_LIST_3_0, 39, C_DigestUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 40, C_DigestKey);
CHECK_FN(CK_FUNCTION_LIST_3_0, 41, C_DigestFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 42, C_SignInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 43, C_Sign);
CHECK_FN(CK_FUNCTION_LIST_3_0, 44, C_SignUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 45, C_SignFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 46, C_SignRecoverInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 47, C_SignRecover);
CHECK_FN(CK_FUNCTION_LIST_3_0, 48, C_VerifyInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 49, C_Verify);
CHECK_FN(CK_FUNCTION_LIST_3_0, 50, C_VerifyUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 51, C_VerifyFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 52, C_VerifyRecoverInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 53, C_VerifyRecover);
CHECK_FN(CK_FUNCTION_LIST_3_0, 54, C_DigestEncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 55, C_DecryptDigestUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 56, C_SignEncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 57, C_DecryptVerifyUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_0, 58, C_GenerateKey);
CHECK_FN(CK_FUNCTION_LIST_3_0, 59, C_GenerateKeyPair);
CHECK_FN(CK_FUNCTION_LIST_3_0, 60, C_WrapKey);
CHECK_FN(CK_FUNCTION_LIST_3_0, 61, C_UnwrapKey);
CHECK_FN(CK_FUNCTION_LIST_3_0, 62, C_DeriveKey);
CHECK_FN(CK_FUNCTION_LIST_3_0, 63, C_SeedRandom);
CHECK_FN(CK_FUNCTION_LIST_3_0, 64, C_GenerateRandom);
CHECK_FN(CK_FUNCTION_LIST_3_0, 65, C_GetFunctionStatus);
CHECK_FN(CK_FUNCTION_LIST_3_0, 66, C_CancelFunction);
CHECK_FN(CK_FUNCTION_LIST_3_0, 67, C_WaitForSlotEvent);
CHECK_FN(CK_FUNCTION_LIST_3_0, 68, C_GetInterfaceList);
CHECK_FN(CK_FUNCTION_LIST_3_0, 69, C_GetInterface);
CHECK_FN(CK_FUNCTION_LIST_3_0, 70, C_LoginUser);
CHECK_FN(CK_FUNCTION_LIST_3_0, 71, C_SessionCancel);
CHECK_FN(CK_FUNCTION_LIST_3_0, 72, C_MessageEncryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 73, C_EncryptMessage);
CHECK_FN(CK_FUNCTION_LIST_3_0, 74, C_EncryptMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_0, 75, C_EncryptMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_0, 76, C_MessageEncryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 77, C_MessageDecryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 78, C_DecryptMessage);
CHECK_FN(CK_FUNCTION_LIST_3_0, 79, C_DecryptMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_0, 80, C_DecryptMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_0, 81, C_MessageDecryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 82, C_MessageSignInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 83, C_SignMessage);
CHECK_FN(CK_FUNCTION_LIST_3_0, 84, C_SignMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_0, 85, C_SignMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_0, 86, C_MessageSignFinal);
CHECK_FN(CK_FUNCTION_LIST_3_0, 87, C_MessageVerifyInit);
CHECK_FN(CK_FUNCTION_LIST_3_0, 88, C_VerifyMessage);
CHECK_FN(CK_FUNCTION_LIST_3_0, 89, C_VerifyMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_0, 90, C_VerifyMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_0, 91, C_MessageVerifyFinal);

/* ============ run-time checks against the loaded module ============ */

static int g_fails = 0;
static int g_checks = 0;

#define CHECK(cond, ...) \
  do { \
    g_checks++; \
    if (!(cond)) { \
      g_fails++; \
      printf("FAIL layout_300:%d: ", __LINE__); \
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
  CK_C_GetInterface get_iface;
  CK_VERSION want;
  CK_INTERFACE_PTR iface = NULL;
  CK_FUNCTION_LIST_3_0_PTR tbl30 = NULL;
  CK_RV rv;
  CK_INFO info;
  size_t i;

  if (argc != 2) {
    printf("usage: layout_300 <libhaskoki.so>\n");
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(h != NULL, "dlopen %s: %s", argv[1], dlerror());
  if (h == NULL) {
    printf("layout_300: %d/%d checks passed\n", g_checks - g_fails, g_checks);
    return 1;
  }
  get_iface = (CK_C_GetInterface)dlsym(h, "C_GetInterface");
  CHECK(get_iface != NULL, "dlsym C_GetInterface");
  if (get_iface == NULL) {
    dlclose(h);
    return 1;
  }

  /* Select interface ("PKCS 11", {3,0}) before initialize (A01/A02). */
  want.major = 3;
  want.minor = 0;
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &want, &iface, 0);
  CHECK(rv == CKR_OK, "C_GetInterface 3.0 rv=%lu", (unsigned long)rv);
  CHECK(iface != NULL, "3.0 interface pointer NULL");
  if (iface == NULL) {
    dlclose(h);
    return 1;
  }
  CHECK(iface->flags == 0, "3.0 interface flags=%lu (fork-safe unclaimed)",
        (unsigned long)iface->flags);
  tbl30 = (CK_FUNCTION_LIST_3_0_PTR)iface->pFunctionList;
  CHECK(tbl30 != NULL, "3.0 function list NULL");
  CHECK(haskoki_version_eq(tbl30->version.major, tbl30->version.minor, 3, 0),
        "3.0 table version %u.%u", tbl30->version.major, tbl30->version.minor);

  /* All 92 entries non-NULL. */
  for (i = 0; i < 92; i++) {
    const void *slot = (const char *)tbl30 + 8 + i * sizeof(void *);
    CHECK(slot_nonnull(slot), "3.0 entry %lu is NULL", (unsigned long)i);
  }

  /* Spots through pinned 3.0 offsets (pre-init): discovery works, new
   * functions observe no live interval. */
  memset(&info, 0, sizeof(info));
  rv = tbl30->C_GetInfo(&info);
  CHECK(rv == CKR_OK, "3.0 C_GetInfo rv=%lu", (unsigned long)rv);
  rv = tbl30->C_LoginUser(0, 0, NULL, 0, NULL, 0);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "3.0 C_LoginUser pre-init rv=%lu",
        (unsigned long)rv);
  rv = tbl30->C_SessionCancel(0, 0);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "3.0 C_SessionCancel pre-init rv=%lu",
        (unsigned long)rv);

  dlclose(h);
  printf("layout_300: %d/%d checks passed\n", g_checks - g_fails, g_checks);
  if (g_fails) {
    printf("FAIL: layout_300\n");
    return 1;
  }
  printf("PASS: layout_300\n");
  return 0;
}
