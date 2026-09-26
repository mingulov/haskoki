/* tests/c/layout_320.c - 3.2 independent layout/prototype probe.
 *
 * Compiled against the single pinned header ONLY
 * (spec/vendor), never against provider-generated types:
 * compile with -I spec/vendor -I cbits.
 * Part of scripts/test-c-abi.sh (acceptance A01/A02 source/ABI slice).
 *
 * Compile time: scalar widths, struct sizes/offsets (incl. CK_INTERFACE
 * and CK_ASYNC_DATA), constant values and all 104
 * CK_FUNCTION_LIST_3_2 positions/prototypes are pinned.
 * Run time: interface-list/discovery matrix, dual-version-table
 * isolation (two clients holding different versioned tables
 * simultaneously), and the lifecycle-aware 3.2 stub policy.
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

_Static_assert(sizeof(CK_ASYNC_DATA) == 40, "CK_ASYNC_DATA size");
_Static_assert(offsetof(CK_ASYNC_DATA, ulVersion) == 0, "async.version");
_Static_assert(offsetof(CK_ASYNC_DATA, pValue) == 8, "async.value");
_Static_assert(offsetof(CK_ASYNC_DATA, ulValue) == 16, "async.valuelen");
_Static_assert(offsetof(CK_ASYNC_DATA, hObject) == 24, "async.object");
_Static_assert(offsetof(CK_ASYNC_DATA, hAdditionalObject) == 32, "async.object2");

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
_Static_assert(CKS_LAST_VALIDATION_OK == 0x1UL, "CKS_LAST_VALIDATION_OK");
/* 3.2 alias pairs. */
_Static_assert(CKM_SHA3_256_KEY_DERIVE == CKM_SHA3_256_KEY_DERIVATION, "3.2 alias sha3");
_Static_assert(CKM_SHA3_256_KEY_DERIVATION == 0x397UL, "3.2 alias sha3 value");
_Static_assert(CK_SP800_108_COUNTER == CK_SP800_108_OPTIONAL_COUNTER, "3.2 alias sp800");
_Static_assert(CK_SP800_108_OPTIONAL_COUNTER == 0x2UL, "3.2 alias sp800 value");

/* 3.2 table: 2 version bytes + 6 pad + 104 pointers. */
_Static_assert(sizeof(CK_FUNCTION_LIST_3_2) == 840, "CK_FUNCTION_LIST_3_2 size");
_Static_assert(sizeof(CK_FUNCTION_LIST_3_0) == 744, "3.0 extent in 3.2 hdrs");
_Static_assert(sizeof(CK_FUNCTION_LIST) == 552, "legacy extent in 3.2 hdrs");
#define CHECK_FN(listtype, idx, name) \
  _Static_assert(offsetof(struct listtype, name) == 8 + (idx)*8, \
                 "offset " #name); \
  _Static_assert(_Generic(((struct listtype *)0)->name, CK_##name: 1, \
                           default: 0), \
                 "prototype " #name)
CHECK_FN(CK_FUNCTION_LIST_3_2, 0, C_Initialize);
CHECK_FN(CK_FUNCTION_LIST_3_2, 1, C_Finalize);
CHECK_FN(CK_FUNCTION_LIST_3_2, 2, C_GetInfo);
CHECK_FN(CK_FUNCTION_LIST_3_2, 3, C_GetFunctionList);
CHECK_FN(CK_FUNCTION_LIST_3_2, 4, C_GetSlotList);
CHECK_FN(CK_FUNCTION_LIST_3_2, 5, C_GetSlotInfo);
CHECK_FN(CK_FUNCTION_LIST_3_2, 6, C_GetTokenInfo);
CHECK_FN(CK_FUNCTION_LIST_3_2, 7, C_GetMechanismList);
CHECK_FN(CK_FUNCTION_LIST_3_2, 8, C_GetMechanismInfo);
CHECK_FN(CK_FUNCTION_LIST_3_2, 9, C_InitToken);
CHECK_FN(CK_FUNCTION_LIST_3_2, 10, C_InitPIN);
CHECK_FN(CK_FUNCTION_LIST_3_2, 11, C_SetPIN);
CHECK_FN(CK_FUNCTION_LIST_3_2, 12, C_OpenSession);
CHECK_FN(CK_FUNCTION_LIST_3_2, 13, C_CloseSession);
CHECK_FN(CK_FUNCTION_LIST_3_2, 14, C_CloseAllSessions);
CHECK_FN(CK_FUNCTION_LIST_3_2, 15, C_GetSessionInfo);
CHECK_FN(CK_FUNCTION_LIST_3_2, 16, C_GetOperationState);
CHECK_FN(CK_FUNCTION_LIST_3_2, 17, C_SetOperationState);
CHECK_FN(CK_FUNCTION_LIST_3_2, 18, C_Login);
CHECK_FN(CK_FUNCTION_LIST_3_2, 19, C_Logout);
CHECK_FN(CK_FUNCTION_LIST_3_2, 20, C_CreateObject);
CHECK_FN(CK_FUNCTION_LIST_3_2, 21, C_CopyObject);
CHECK_FN(CK_FUNCTION_LIST_3_2, 22, C_DestroyObject);
CHECK_FN(CK_FUNCTION_LIST_3_2, 23, C_GetObjectSize);
CHECK_FN(CK_FUNCTION_LIST_3_2, 24, C_GetAttributeValue);
CHECK_FN(CK_FUNCTION_LIST_3_2, 25, C_SetAttributeValue);
CHECK_FN(CK_FUNCTION_LIST_3_2, 26, C_FindObjectsInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 27, C_FindObjects);
CHECK_FN(CK_FUNCTION_LIST_3_2, 28, C_FindObjectsFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 29, C_EncryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 30, C_Encrypt);
CHECK_FN(CK_FUNCTION_LIST_3_2, 31, C_EncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 32, C_EncryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 33, C_DecryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 34, C_Decrypt);
CHECK_FN(CK_FUNCTION_LIST_3_2, 35, C_DecryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 36, C_DecryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 37, C_DigestInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 38, C_Digest);
CHECK_FN(CK_FUNCTION_LIST_3_2, 39, C_DigestUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 40, C_DigestKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 41, C_DigestFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 42, C_SignInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 43, C_Sign);
CHECK_FN(CK_FUNCTION_LIST_3_2, 44, C_SignUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 45, C_SignFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 46, C_SignRecoverInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 47, C_SignRecover);
CHECK_FN(CK_FUNCTION_LIST_3_2, 48, C_VerifyInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 49, C_Verify);
CHECK_FN(CK_FUNCTION_LIST_3_2, 50, C_VerifyUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 51, C_VerifyFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 52, C_VerifyRecoverInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 53, C_VerifyRecover);
CHECK_FN(CK_FUNCTION_LIST_3_2, 54, C_DigestEncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 55, C_DecryptDigestUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 56, C_SignEncryptUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 57, C_DecryptVerifyUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 58, C_GenerateKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 59, C_GenerateKeyPair);
CHECK_FN(CK_FUNCTION_LIST_3_2, 60, C_WrapKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 61, C_UnwrapKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 62, C_DeriveKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 63, C_SeedRandom);
CHECK_FN(CK_FUNCTION_LIST_3_2, 64, C_GenerateRandom);
CHECK_FN(CK_FUNCTION_LIST_3_2, 65, C_GetFunctionStatus);
CHECK_FN(CK_FUNCTION_LIST_3_2, 66, C_CancelFunction);
CHECK_FN(CK_FUNCTION_LIST_3_2, 67, C_WaitForSlotEvent);
CHECK_FN(CK_FUNCTION_LIST_3_2, 68, C_GetInterfaceList);
CHECK_FN(CK_FUNCTION_LIST_3_2, 69, C_GetInterface);
CHECK_FN(CK_FUNCTION_LIST_3_2, 70, C_LoginUser);
CHECK_FN(CK_FUNCTION_LIST_3_2, 71, C_SessionCancel);
CHECK_FN(CK_FUNCTION_LIST_3_2, 72, C_MessageEncryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 73, C_EncryptMessage);
CHECK_FN(CK_FUNCTION_LIST_3_2, 74, C_EncryptMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_2, 75, C_EncryptMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_2, 76, C_MessageEncryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 77, C_MessageDecryptInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 78, C_DecryptMessage);
CHECK_FN(CK_FUNCTION_LIST_3_2, 79, C_DecryptMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_2, 80, C_DecryptMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_2, 81, C_MessageDecryptFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 82, C_MessageSignInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 83, C_SignMessage);
CHECK_FN(CK_FUNCTION_LIST_3_2, 84, C_SignMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_2, 85, C_SignMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_2, 86, C_MessageSignFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 87, C_MessageVerifyInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 88, C_VerifyMessage);
CHECK_FN(CK_FUNCTION_LIST_3_2, 89, C_VerifyMessageBegin);
CHECK_FN(CK_FUNCTION_LIST_3_2, 90, C_VerifyMessageNext);
CHECK_FN(CK_FUNCTION_LIST_3_2, 91, C_MessageVerifyFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 92, C_EncapsulateKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 93, C_DecapsulateKey);
CHECK_FN(CK_FUNCTION_LIST_3_2, 94, C_VerifySignatureInit);
CHECK_FN(CK_FUNCTION_LIST_3_2, 95, C_VerifySignature);
CHECK_FN(CK_FUNCTION_LIST_3_2, 96, C_VerifySignatureUpdate);
CHECK_FN(CK_FUNCTION_LIST_3_2, 97, C_VerifySignatureFinal);
CHECK_FN(CK_FUNCTION_LIST_3_2, 98, C_GetSessionValidationFlags);
CHECK_FN(CK_FUNCTION_LIST_3_2, 99, C_AsyncComplete);
CHECK_FN(CK_FUNCTION_LIST_3_2, 100, C_AsyncGetID);
CHECK_FN(CK_FUNCTION_LIST_3_2, 101, C_AsyncJoin);
CHECK_FN(CK_FUNCTION_LIST_3_2, 102, C_WrapKeyAuthenticated);
CHECK_FN(CK_FUNCTION_LIST_3_2, 103, C_UnwrapKeyAuthenticated);

/* ============ run-time checks against the loaded module ============ */

static int g_fails = 0;
static int g_checks = 0;

#define CHECK(cond, ...) \
  do { \
    g_checks++; \
    if (!(cond)) { \
      g_fails++; \
      printf("FAIL layout_320:%d: ", __LINE__); \
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
  CK_C_GetInterfaceList get_list;
  CK_C_GetInterface get_iface;
  CK_ULONG count = 0;
  CK_RV rv;
  CK_INTERFACE got[4];
  CK_VERSION want;
  CK_INTERFACE_PTR i30 = NULL;
  CK_INTERFACE_PTR i31 = NULL;
  CK_INTERFACE_PTR i32 = NULL;
  CK_INTERFACE_PTR idef = NULL;
  CK_FUNCTION_LIST_3_0_PTR tbl30 = NULL;
  CK_FUNCTION_LIST_3_2_PTR tbl32 = NULL;
  CK_INFO info30;
  CK_INFO info32;
  CK_OBJECT_HANDLE key = 0;
  CK_ULONG ctlen = 0;
  size_t i;
  /* Canary-guarded short buffer: [canary][1 entry][canary]. */
  unsigned char guarded[16 + sizeof(CK_INTERFACE) + 16];
  CK_INTERFACE_PTR one = (CK_INTERFACE_PTR)(guarded + 16);

  if (argc != 2) {
    printf("usage: layout_320 <libhaskoki.so>\n");
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(h != NULL, "dlopen %s: %s", argv[1], dlerror());
  if (h == NULL) {
    printf("layout_320: %d/%d checks passed\n", g_checks - g_fails, g_checks);
    return 1;
  }
  get_list = (CK_C_GetInterfaceList)dlsym(h, "C_GetInterfaceList");
  get_iface = (CK_C_GetInterface)dlsym(h, "C_GetInterface");
  CHECK(get_list != NULL, "dlsym C_GetInterfaceList");
  CHECK(get_iface != NULL, "dlsym C_GetInterface");
  if (get_list == NULL || get_iface == NULL) {
    dlclose(h);
    return 1;
  }

  /* ---- interface-list matrix (A01, pre-init) ---- */
  rv = get_list(NULL, &count);
  CHECK(rv == CKR_OK, "list NULL rv=%lu", (unsigned long)rv);
  CHECK(count == 3, "list count=%lu, want 3", (unsigned long)count);
  rv = get_list(NULL, NULL);
  CHECK(rv == CKR_ARGUMENTS_BAD, "list NULL count rv=%lu", (unsigned long)rv);

  haskoki_canary_fill(guarded, 16);
  haskoki_canary_fill(guarded + 16 + sizeof(CK_INTERFACE), 16);
  memset(one, 0xCC, sizeof(*one));
  count = 1;
  rv = get_list(one, &count);
  CHECK(rv == CKR_BUFFER_TOO_SMALL, "list short rv=%lu", (unsigned long)rv);
  CHECK(count == 3, "list short count=%lu", (unsigned long)count);
  CHECK(haskoki_canary_check(guarded, 16) &&
            haskoki_canary_check(guarded + 16 + sizeof(CK_INTERFACE), 16),
        "list short-buffer overrun");
  {
    int untouched = 1;
    size_t k;
    for (k = 0; k < sizeof(*one); k++) {
      if (((unsigned char *)one)[k] != 0xCC) {
        untouched = 0;
      }
    }
    CHECK(untouched, "list short-buffer wrote output");
  }

  memset(got, 0xCC, sizeof(got));
  count = 4;
  rv = get_list(got, &count);
  CHECK(rv == CKR_OK, "list exact rv=%lu", (unsigned long)rv);
  CHECK(count == 3, "list exact count=%lu", (unsigned long)count);
  for (i = 0; i < 3; i++) {
    CHECK(strcmp((const char *)got[i].pInterfaceName, "PKCS 11") == 0,
          "iface %lu name", (unsigned long)i);
    CHECK(got[i].flags == 0, "iface %lu flags=%lu", (unsigned long)i,
          (unsigned long)got[i].flags);
    CHECK(got[i].pFunctionList != NULL, "iface %lu list NULL", (unsigned long)i);
  }

  /* ---- interface selection matrix (A02) ---- */
  want.major = 3;
  want.minor = 0;
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &want, &i30, 0);
  CHECK(rv == CKR_OK, "get 3.0 rv=%lu", (unsigned long)rv);
  want.major = 3;
  want.minor = 1;
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &want, &i31, 0);
  CHECK(rv == CKR_OK, "get 3.1 rv=%lu", (unsigned long)rv);
  want.major = 3;
  want.minor = 2;
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &want, &i32, 0);
  CHECK(rv == CKR_OK, "get 3.2 rv=%lu", (unsigned long)rv);
  rv = get_iface(NULL, NULL, &idef, 0);
  CHECK(rv == CKR_OK, "get default rv=%lu", (unsigned long)rv);
  if (i30 == NULL || i31 == NULL || i32 == NULL || idef == NULL) {
    dlclose(h);
    return 1;
  }
  CHECK(idef->pFunctionList == i32->pFunctionList, "default must be 3.2");
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", NULL, &idef, 0);
  CHECK(rv == CKR_OK && idef->pFunctionList == i32->pFunctionList,
        "name-only lookup must be 3.2");
  rv = get_iface((CK_UTF8CHAR_PTR)"No Such Interface", NULL, &idef, 0);
  CHECK(rv == CKR_ARGUMENTS_BAD, "unknown name rv=%lu", (unsigned long)rv);
  want.major = 9;
  want.minor = 9;
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &want, &idef, 0);
  CHECK(rv == CKR_ARGUMENTS_BAD, "unknown version rv=%lu", (unsigned long)rv);
  want.major = 2;
  want.minor = 40;
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", &want, &idef, 0);
  CHECK(rv == CKR_ARGUMENTS_BAD, "legacy version via GetInterface rv=%lu",
        (unsigned long)rv);
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", NULL, &idef,
                 CKF_INTERFACE_FORK_SAFE);
  CHECK(rv == CKR_ARGUMENTS_BAD, "unadvertised-flag lookup rv=%lu",
        (unsigned long)rv);
  rv = get_iface((CK_UTF8CHAR_PTR)"PKCS 11", NULL, NULL, 0);
  CHECK(rv == CKR_ARGUMENTS_BAD, "NULL out-param rv=%lu", (unsigned long)rv);

  /* ---- dual-version-table isolation ---- */
  tbl30 = (CK_FUNCTION_LIST_3_0_PTR)i30->pFunctionList;
  tbl32 = (CK_FUNCTION_LIST_3_2_PTR)i32->pFunctionList;
  CHECK((const void *)tbl30 != (const void *)tbl32, "3.0/3.2 share an instance");
  CHECK(haskoki_version_eq(tbl30->version.major, tbl30->version.minor, 3, 0),
        "3.0 version %u.%u", tbl30->version.major, tbl30->version.minor);
  CHECK(haskoki_version_eq(tbl32->version.major, tbl32->version.minor, 3, 2),
        "3.2 version %u.%u", tbl32->version.major, tbl32->version.minor);
  for (i = 0; i < 104; i++) {
    const void *slot = (const char *)tbl32 + 8 + i * sizeof(void *);
    CHECK(slot_nonnull(slot), "3.2 entry %lu is NULL", (unsigned long)i);
  }
  /* Use both tables: selecting one must not change the other's context. */
  memset(&info30, 0, sizeof(info30));
  memset(&info32, 0, sizeof(info32));
  rv = tbl30->C_GetInfo(&info30);
  CHECK(rv == CKR_OK, "3.0 C_GetInfo rv=%lu", (unsigned long)rv);
  rv = tbl32->C_GetInfo(&info32);
  CHECK(rv == CKR_OK, "3.2 C_GetInfo rv=%lu", (unsigned long)rv);
  CHECK(haskoki_version_eq(tbl30->version.major, tbl30->version.minor, 3, 0),
        "3.0 version moved");
  CHECK(haskoki_version_eq(tbl32->version.major, tbl32->version.minor, 3, 2),
        "3.2 version moved");
  CHECK(haskoki_version_eq(info30.cryptokiVersion.major,
                           info30.cryptokiVersion.minor, 2, 40),
        "info via 3.0 reports %u.%u", info30.cryptokiVersion.major,
        info30.cryptokiVersion.minor);

  /* ---- lifecycle-aware 3.2 entries: pre -> live -> pre ----
   * (encapsulate is ROUTED: a NULL mechanism is an argument
   * error on a live token, never NOT_SUPPORTED). */
  rv = tbl32->C_EncapsulateKey(0, NULL, 0, NULL, 0, NULL, &ctlen, &key);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "encaps pre-init rv=%lu",
        (unsigned long)rv);
  rv = tbl32->C_Initialize(NULL);
  CHECK(rv == CKR_OK, "init via 3.2 rv=%lu", (unsigned long)rv);
  rv = tbl32->C_EncapsulateKey(0, NULL, 0, NULL, 0, NULL, &ctlen, &key);
  CHECK(rv == CKR_ARGUMENTS_BAD, "encaps live rv=%lu",
        (unsigned long)rv);
  CHECK(haskoki_version_eq(tbl30->version.major, tbl30->version.minor, 3, 0),
        "3.0 version moved across init");
  rv = tbl32->C_Finalize(NULL);
  CHECK(rv == CKR_OK, "finalize via 3.2 rv=%lu", (unsigned long)rv);
  rv = tbl32->C_EncapsulateKey(0, NULL, 0, NULL, 0, NULL, &ctlen, &key);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "encaps post-finalize rv=%lu",
        (unsigned long)rv);

  dlclose(h);
  printf("layout_320: %d/%d checks passed\n", g_checks - g_fails, g_checks);
  if (g_fails) {
    printf("FAIL: layout_320\n");
    return 1;
  }
  printf("PASS: layout_320\n");
  return 0;
}
