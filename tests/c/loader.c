/* tests/c/loader.c — independent loader harness.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module, resolves C_GetFunctionList via dlsym(), and
 * exercises acceptance cases A01–A06 plus the digest slice (real
 * sessions, provisioned token, 118-row catalog, SHA-1).
 *
 * Usage: loader <path-to-libhaskoki.so>
 * Exit status: 0 iff every check passes.
 *
 * Independence note (honest limitation): the minimal cryptoki
 * subset below is hand-written from the published PKCS#11 v2.40 function
 * order. It is compiled separately from the provider and reaches it only
 * through dlopen/dlsym, but it does NOT come from byte-pinned
 * headers. The provider side uses pinned headers plus generated
 * tables and independent layout probes; a transposition shared by
 * both hand-written copies would not be caught here.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* ================= local cryptoki subset (BEGIN) =================
 * Hand-written from the PKCS#11 v2.40 legacy interface order.
 * SUPERSEDED: replaced by byte-locked headers + generated tables.
 */
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_USER_TYPE;
typedef unsigned long CK_NOTIFICATION;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_UTF8CHAR;
typedef unsigned char CK_BBOOL;
typedef void *CK_VOID_PTR;

typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;

/* Return codes used by this harness (PKCS#11 v2.40 values). */
#define CKR_OK 0x00000000UL
#define CKR_SLOT_ID_INVALID 0x00000003UL
#define CKR_GENERAL_ERROR 0x00000005UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_NEED_TO_CREATE_THREADS 0x00000009UL
#define CKR_CANT_LOCK 0x0000000AUL
#define CKR_FUNCTION_NOT_PARALLEL 0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054UL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID 0x00000071UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

/* Mechanisms / flags used by this harness. */
#define CKM_SHA_1 0x00000220UL
#define CKM_SHA256 0x00000250UL
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK 0x00000002UL
#define CKF_DIGEST 0x00000400UL
/* Session flags (sessions are real; open needs CKF_SERIAL_SESSION). */
#define CKF_SERIAL_SESSION 0x00000004UL
#define CKF_RW_SESSION 0x00000002UL

typedef struct CK_VERSION {
  unsigned char major;
  unsigned char minor;
} CK_VERSION;

typedef struct CK_INFO {
  CK_VERSION cryptokiVersion;
  unsigned char manufacturerID[32];
  CK_FLAGS flags;
  unsigned char libraryDescription[32];
  CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_INFO *CK_INFO_PTR;

typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;
  CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
  CK_ULONG ulMinKeySize;
  CK_ULONG ulMaxKeySize;
  CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

/* Opaque (pointer-only here); full layouts live in the pinned headers. */
typedef struct CK_SLOT_INFO CK_SLOT_INFO;
typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;
typedef struct CK_TOKEN_INFO CK_TOKEN_INFO;
typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;
typedef struct CK_SESSION_INFO CK_SESSION_INFO;
typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;
typedef struct CK_ATTRIBUTE CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession,
                           CK_NOTIFICATION event, CK_VOID_PTR pApplication);

typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR *ppMutex);
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS *CK_C_INITIALIZE_ARGS_PTR;

/* Legacy 2.40 function-pointer typedefs, canonical order. */
typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_GetInfo)(CK_INFO_PTR pInfo);
struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL tokenPresent,
                                  CK_SLOT_ID_PTR pSlotList,
                                  CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetMechanismList)(CK_SLOT_ID slotID,
                                       CK_MECHANISM_TYPE_PTR pMechanismList,
                                       CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID,
                                       CK_MECHANISM_TYPE type,
                                       CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*CK_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                                CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
typedef CK_RV (*CK_C_InitPIN)(CK_SESSION_HANDLE hSession,
                              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_SetPIN)(CK_SESSION_HANDLE hSession,
                             CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                             CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
                                  CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                  CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (*CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession,
                                     CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetOperationState)(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pOperationState,
                                        CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*CK_C_SetOperationState)(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pOperationState,
                                        CK_ULONG ulOperationStateLen,
                                        CK_OBJECT_HANDLE hEncryptionKey,
                                        CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                            CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CreateObject)(CK_SESSION_HANDLE hSession,
                                   CK_ATTRIBUTE_PTR pTemplate,
                                   CK_ULONG ulCount,
                                   CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*CK_C_CopyObject)(CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE hObject,
                                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                 CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*CK_C_DestroyObject)(CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE hObject);
typedef CK_RV (*CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE hObject,
                                    CK_ULONG_PTR pulSize);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount);
typedef CK_RV (*CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
                                      CK_ATTRIBUTE_PTR pTemplate,
                                      CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE hSession,
                                  CK_OBJECT_HANDLE_PTR phObject,
                                  CK_ULONG ulMaxObjectCount,
                                  CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_EncryptInit)(CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                              CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                              CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                    CK_BYTE_PTR pEncryptedPart,
                                    CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pLastEncryptedPart,
                                   CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptInit)(CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Decrypt)(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedData,
                              CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                              CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pEncryptedPart,
                                    CK_ULONG ulEncryptedPartLen,
                                    CK_BYTE_PTR pPart,
                                    CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pLastPart,
                                   CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*CK_C_DigestInit)(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                             CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                             CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_DigestKey)(CK_SESSION_HANDLE hSession,
                                CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_DigestFinal)(CK_SESSION_HANDLE hSession,
                                  CK_BYTE_PTR pDigest,
                                  CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE hSession,
                               CK_MECHANISM_PTR pMechanism,
                               CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                           CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                           CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                 CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_SignFinal)(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pSignature,
                                CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession,
                                      CK_MECHANISM_PTR pMechanism,
                                      CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                                  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                                  CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                             CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                             CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession,
                                   CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession,
                                  CK_BYTE_PTR pSignature,
                                  CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession,
                                        CK_MECHANISM_PTR pMechanism,
                                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pSignature,
                                    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                                    CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pPart,
                                          CK_ULONG ulPartLen,
                                          CK_BYTE_PTR pEncryptedPart,
                                          CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pEncryptedPart,
                                          CK_ULONG ulEncryptedPartLen,
                                          CK_BYTE_PTR pPart,
                                          CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                        CK_BYTE_PTR pEncryptedPart,
                                        CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pEncryptedPart,
                                          CK_ULONG ulEncryptedPartLen,
                                          CK_BYTE_PTR pPart,
                                          CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                  CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_GenerateKeyPair)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*CK_C_WrapKey)(CK_SESSION_HANDLE hSession,
                              CK_MECHANISM_PTR pWrappingMechanism,
                              CK_OBJECT_HANDLE hWrappingKey,
                              CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
                              CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM_PTR pUnwrappingMechanism,
                                CK_OBJECT_HANDLE hUnwrappingKey,
                                CK_BYTE_PTR pWrappedKey,
                                CK_ULONG ulWrappedKeyLen,
                                CK_ATTRIBUTE_PTR pTemplate,
                                CK_ULONG ulAttributeCount,
                                CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_DeriveKey)(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM_PTR pMechanism,
                                CK_OBJECT_HANDLE hBaseKey,
                                CK_ATTRIBUTE_PTR pTemplate,
                                CK_ULONG ulAttributeCount,
                                CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                                 CK_ULONG ulSeedLen);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR pRandomData,
                                     CK_ULONG ulRandomLen);
typedef CK_RV (*CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                                       CK_VOID_PTR pReserved);

struct CK_FUNCTION_LIST {
  CK_VERSION version;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetSlotInfo C_GetSlotInfo;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_SetPIN C_SetPIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_SetOperationState C_SetOperationState;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_GetObjectSize C_GetObjectSize;
  CK_C_GetAttributeValue C_GetAttributeValue;
  CK_C_SetAttributeValue C_SetAttributeValue;
  CK_C_FindObjectsInit C_FindObjectsInit;
  CK_C_FindObjects C_FindObjects;
  CK_C_FindObjectsFinal C_FindObjectsFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_DigestKey C_DigestKey;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_GenerateKey C_GenerateKey;
  CK_C_GenerateKeyPair C_GenerateKeyPair;
  CK_C_WrapKey C_WrapKey;
  CK_C_UnwrapKey C_UnwrapKey;
  CK_C_DeriveKey C_DeriveKey;
  CK_C_SeedRandom C_SeedRandom;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_GetFunctionStatus C_GetFunctionStatus;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};
/* ================= local cryptoki subset (END) ================= */

#define CK_FN_COUNT 68u

static int g_failures = 0;
static int g_checks = 0;

#define EXPECT_TRUE(cond, label)                                              \
  do {                                                                        \
    g_checks++;                                                               \
    if (!(cond)) {                                                            \
      g_failures++;                                                           \
      printf("  FAIL %s (%s:%d)\n", label, __FILE__, __LINE__);                \
    }                                                                         \
  } while (0)

#define EXPECT_RV(got, want, label)                                           \
  do {                                                                        \
    CK_RV _got = (got);                                                       \
    CK_RV _want = (want);                                                     \
    g_checks++;                                                               \
    if (_got != _want) {                                                      \
      g_failures++;                                                           \
      printf("  FAIL %s: got 0x%lx want 0x%lx (%s:%d)\n", label,                \
             (unsigned long)_got, (unsigned long)_want, __FILE__, __LINE__);  \
    }                                                                         \
  } while (0)

#define CASE_BEGIN(id, title)                                                 \
  do {                                                                        \
    printf("%s: %s\n", id, title);                                            \
  } while (0)

#define CASE_END(id)                                                          \
  do {                                                                        \
    printf("%s: %s\n", id, _case_ok() ? "PASS" : "FAIL");                      \
  } while (0)

static int g_case_failures_at_start = 0;

static void case_mark_start(void) { g_case_failures_at_start = g_failures; }

static int _case_ok(void) { return g_failures == g_case_failures_at_start; }

/* Dummy session handle: the original digest slice ignored the handle
 * value. Since session routing, handle 0 is never valid: every
 * session-scoped call validates the handle first
 * (CKR_SESSION_HANDLE_INVALID). */
#define DUMMY_SESSION 0UL
/* Routed mechanism-catalog row count (pinned exactly here and in
 * consumer_discovery; the generator is scripts/mech_catalog.py). */
#define ROUTED_MECH_COUNT 270UL

/* ---------- A05 mutex-callback fixtures ---------- */

static long g_mu_created = 0;
static long g_mu_destroyed = 0;
static long g_mu_locked = 0;
static long g_mu_unlocked = 0;

static void mu_reset(void) {
  g_mu_created = 0;
  g_mu_destroyed = 0;
  g_mu_locked = 0;
  g_mu_unlocked = 0;
}

static CK_RV mu_create(CK_VOID_PTR *pp) {
  pthread_mutex_t *m;
  if (pp == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  m = malloc(sizeof(*m));
  if (m == NULL) {
    return CKR_GENERAL_ERROR;
  }
  pthread_mutex_init(m, NULL);
  *pp = m;
  __atomic_add_fetch(&g_mu_created, 1, __ATOMIC_SEQ_CST);
  return CKR_OK;
}

static CK_RV mu_destroy(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  pthread_mutex_destroy((pthread_mutex_t *)p);
  free(p);
  __atomic_add_fetch(&g_mu_destroyed, 1, __ATOMIC_SEQ_CST);
  return CKR_OK;
}

static CK_RV mu_fail_create(CK_VOID_PTR *pp) {
  (void)pp;
  return CKR_GENERAL_ERROR;
}

static CK_RV mu_lock(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  pthread_mutex_lock((pthread_mutex_t *)p);
  __atomic_add_fetch(&g_mu_locked, 1, __ATOMIC_SEQ_CST);
  return CKR_OK;
}

static CK_RV mu_unlock(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  __atomic_add_fetch(&g_mu_unlocked, 1, __ATOMIC_SEQ_CST);
  pthread_mutex_unlock((pthread_mutex_t *)p);
  return CKR_OK;
}

/* ---------- A04 worker ---------- */

typedef struct {
  CK_FUNCTION_LIST_PTR p11;
  int iters;
  int failed;
} worker_arg_t;

static void *worker_main(void *arg) {
  worker_arg_t *w = (worker_arg_t *)arg;
  int i;
  for (i = 0; i < w->iters; i++) {
    CK_INFO info;
    CK_ULONG n = 0;
    CK_ULONG nm = 0;
    if (w->p11->C_GetInfo(&info) != CKR_OK) {
      w->failed = 1;
      return NULL;
    }
    if (w->p11->C_GetSlotList(0, NULL, &n) != CKR_OK || n != 1) {
      w->failed = 1;
      return NULL;
    }
    /* Full catalog fill: sized by the pinned row count. */
    {
      CK_MECHANISM_TYPE ms[ROUTED_MECH_COUNT];
      CK_ULONG nq = 0;
      int j, found = 0;
      if (w->p11->C_GetMechanismList(0, NULL, &nq) != CKR_OK ||
          nq != ROUTED_MECH_COUNT) {
        w->failed = 1;
        return NULL;
      }
      nm = ROUTED_MECH_COUNT;
      if (w->p11->C_GetMechanismList(0, ms, &nm) != CKR_OK ||
          nm != ROUTED_MECH_COUNT) {
        w->failed = 1;
        return NULL;
      }
      for (j = 0; j < (int)nm; j++) {
        if (ms[j] == CKM_SHA256) {
          found = 1;
        }
      }
      if (!found) {
        w->failed = 1;
        return NULL;
      }
    }
  }
  return NULL;
}

/* ---------- canary buffers ---------- */

#define CANARY_MAGIC 0xC0FFEE11BADC0DEULL

typedef struct {
  uint64_t pre;
  CK_INFO info;
  uint64_t post;
} canary_info_t;

typedef struct {
  uint64_t pre;
  unsigned char digest[32];
  uint64_t post;
} canary_digest_t;

/* ---------- cases ---------- */

/* A01: discovery before initialize; null/sufficient forms; table wiring. */
static void case_a01(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  CK_FUNCTION_LIST_PTR q = NULL;
  canary_info_t c;
  unsigned i;
  void **slots;

  case_mark_start();
  CASE_BEGIN("A01", "discovery before initialize, null/sufficient forms");

  /* Null form rejected without crashing. */
  rv = p11->C_GetFunctionList(NULL);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetFunctionList(NULL)");

  /* Sufficient form. */
  rv = p11->C_GetFunctionList(&q);
  EXPECT_RV(rv, CKR_OK, "C_GetFunctionList(&q)");
  EXPECT_TRUE(q != NULL, "table pointer non-NULL");
  EXPECT_TRUE(q == p11, "stable table pointer");

  /* Legacy version. */
  EXPECT_TRUE(p11->version.major == 2 && p11->version.minor == 40,
              "table version is 2.40");

  /* Layout self-check (same-compiler; cross-checked against real headers). */
  EXPECT_TRUE(sizeof(struct CK_FUNCTION_LIST) ==
                  sizeof(void *) * (CK_FN_COUNT + 1),
              "CK_FUNCTION_LIST size == 8 + 68*8");
  EXPECT_TRUE(__builtin_offsetof(struct CK_FUNCTION_LIST, C_Initialize) ==
                  sizeof(void *),
              "C_Initialize offset");

  /* Every table slot wired (no NULL function pointers). */
  slots = (void **)&p11->C_Initialize;
  for (i = 0; i < CK_FN_COUNT; i++) {
    if (slots[i] == NULL) {
      char label[64];
      snprintf(label, sizeof(label), "table slot %u non-NULL", i);
      EXPECT_TRUE(0, label);
      break;
    }
  }
  g_checks++;
  if (i == CK_FN_COUNT) {
    /* counted as one passing check */
  } else {
    g_failures++;
  }

  /* C_GetInfo null/sufficient forms (callable pre-init). */
  rv = p11->C_GetInfo(NULL);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "C_GetInfo(NULL) pre-init");
  c.pre = CANARY_MAGIC;
  c.post = CANARY_MAGIC;
  memset(&c.info, 0xA5, sizeof(c.info));
  rv = p11->C_GetInfo(&c.info);
  EXPECT_RV(rv, CKR_OK, "C_GetInfo(&info) pre-init");
  EXPECT_TRUE(c.pre == CANARY_MAGIC && c.post == CANARY_MAGIC,
              "C_GetInfo canaries intact");

  /* Initialized-only call pre-init sees no state. */
  {
    CK_ULONG n = 0xDEADu;
    rv = p11->C_GetSlotList(0, NULL, &n);
    EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "C_GetSlotList pre-init");
  }

  CASE_END("A01");
}

/* A02: version metadata consistency (2.40 only). */
static void case_a02(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  CK_INFO info;
  case_mark_start();
  CASE_BEGIN("A02", "version metadata consistency (2.40 slice)");
  memset(&info, 0, sizeof(info));
  rv = p11->C_GetInfo(&info);
  EXPECT_RV(rv, CKR_OK, "C_GetInfo");
  EXPECT_TRUE(info.cryptokiVersion.major == 2 &&
                  info.cryptokiVersion.minor == 40,
              "cryptokiVersion == 2.40");
  EXPECT_TRUE(info.cryptokiVersion.major == p11->version.major &&
                  info.cryptokiVersion.minor == p11->version.minor,
              "info/table version agree");
  /* libraryVersion tracks the package (0.3), distinct from cryptoki 2.40. */
  EXPECT_TRUE(info.libraryVersion.major == 0 && info.libraryVersion.minor == 3,
              "libraryVersion == 0.3");
  EXPECT_TRUE(
      memcmp(info.manufacturerID, "haskoki", 7) == 0, "manufacturer prefix");
  EXPECT_TRUE(
      memcmp(info.libraryDescription, "haskoki", 7) == 0, "description prefix");
  /* Space padding, no NUL terminator inside fixed fields. */
  EXPECT_TRUE(info.manufacturerID[31] == ' ', "manufacturer padding");
  EXPECT_TRUE(info.libraryDescription[31] == ' ', "description padding");
  EXPECT_TRUE(memchr(info.manufacturerID, '\0', 32) == NULL,
              "manufacturer has no NUL");
  EXPECT_TRUE(memchr(info.libraryDescription, '\0', 32) == NULL,
              "description has no NUL");
  EXPECT_TRUE(info.flags == 0, "info flags zero");
  CASE_END("A02");
}

/* A03: init/finalize cycles, post-finalize invalidation, re-init (no
 * hs_exit: the second cycle proves the RTS survived finalization). */
static void case_a03(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  CK_ULONG n;
  CK_SLOT_ID slot = 0xBEEFu;
  case_mark_start();
  CASE_BEGIN("A03", "init/finalize cycles + post-finalize invalidation");

  /* Cycle 1. */
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "cycle1 init");
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED, "double init rejected");
  n = 0;
  rv = p11->C_GetSlotList(0, NULL, &n);
  EXPECT_RV(rv, CKR_OK, "slot count query");
  EXPECT_TRUE(n == 1, "one slot");
  n = 1;
  rv = p11->C_GetSlotList(0, &slot, &n);
  EXPECT_RV(rv, CKR_OK, "slot list fill");
  EXPECT_TRUE(slot == 0 && n == 1, "slot id 0");
  /* A provisioned token is routed: token-present queries report one slot. */
  n = 0xDEADu;
  rv = p11->C_GetSlotList(1, NULL, &n);
  EXPECT_RV(rv, CKR_OK, "token-present count query");
  EXPECT_TRUE(n == 1, "one token-present slot");
  slot = 0xBEEFu;
  n = 1;
  rv = p11->C_GetSlotList(1, &slot, &n);
  EXPECT_RV(rv, CKR_OK, "token-present list fill");
  EXPECT_TRUE(slot == 0 && n == 1, "token-present slot id 0");
  n = 0;
  rv = p11->C_GetSlotList(0, &slot, &n);
  EXPECT_RV(rv, CKR_BUFFER_TOO_SMALL, "slot list too-small");
  EXPECT_TRUE(n == 1, "too-small reports count");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "cycle1 finalize");
  /* Post-finalize: no previous state visible. */
  n = 0xDEADu;
  rv = p11->C_GetSlotList(0, NULL, &n);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "post-finalize slot list");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "double finalize rejected");
  /* Metadata still available after finalize (pure static info). */
  {
    CK_INFO info;
    rv = p11->C_GetInfo(&info);
    EXPECT_RV(rv, CKR_OK, "post-finalize get-info");
  }

  /* Cycle 2 (proves no RTS shutdown in finalize). */
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "cycle2 init");
  n = 0;
  rv = p11->C_GetSlotList(0, NULL, &n);
  EXPECT_RV(rv, CKR_OK, "cycle2 slot count");
  EXPECT_TRUE(n == 1, "cycle2 one slot");
  /* Fresh interval: digest not active on a real session; the dummy
   * handle is rejected before any state is consulted. */
  {
    CK_ULONG len = 0;
    unsigned char buf[32];
    CK_SESSION_HANDLE sess = 0;
    rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, &sess);
    EXPECT_RV(rv, CKR_OK, "cycle2 open session");
    EXPECT_TRUE(sess != 0, "cycle2 session handle valid");
    len = sizeof(buf);
    rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
    EXPECT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "fresh digest state");
    len = sizeof(buf);
    rv = p11->C_Digest(DUMMY_SESSION, (CK_BYTE_PTR) "abc", 3, buf, &len);
    EXPECT_RV(rv, CKR_SESSION_HANDLE_INVALID, "dummy handle invalid");
    rv = p11->C_CloseSession(sess);
    EXPECT_RV(rv, CKR_OK, "cycle2 close session");
  }
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "cycle2 finalize");

  CASE_END("A03");
}

/* A04: concurrent native-thread entry. */
static void case_a04(CK_FUNCTION_LIST_PTR p11) {
  enum { NTHREADS = 4, ITERS = 300 };
  pthread_t th[NTHREADS];
  worker_arg_t args[NTHREADS];
  int i, created = 1;
  CK_RV rv;
  case_mark_start();
  CASE_BEGIN("A04", "native pthread entry (4x300 mixed calls)");
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "a04 init");
  for (i = 0; i < NTHREADS; i++) {
    args[i].p11 = p11;
    args[i].iters = ITERS;
    args[i].failed = 0;
    if (pthread_create(&th[i], NULL, worker_main, &args[i]) != 0) {
      created = 0;
    }
  }
  EXPECT_TRUE(created, "threads created");
  for (i = 0; i < NTHREADS; i++) {
    pthread_join(th[i], NULL);
    if (args[i].failed) {
      char label[64];
      snprintf(label, sizeof(label), "worker %d clean", i);
      EXPECT_TRUE(0, label);
    }
  }
  g_checks++;
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "a04 finalize");
  CASE_END("A04");
}

/* A05: mutex negotiation table + thread-prohibition refusal. */
static void case_a05(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  CK_C_INITIALIZE_ARGS args;
  case_mark_start();
  CASE_BEGIN("A05", "mutex negotiation + thread-prohibition limit");

  /* 1. Plain init, no callbacks. */
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "init(NULL)");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "finalize after init(NULL)");

  /* 2. Full callbacks + OS locking flag: callbacks actually used. */
  mu_reset();
  memset(&args, 0, sizeof(args));
  args.CreateMutex = mu_create;
  args.DestroyMutex = mu_destroy;
  args.LockMutex = mu_lock;
  args.UnlockMutex = mu_unlock;
  args.flags = CKF_OS_LOCKING_OK;
  args.pReserved = NULL;
  rv = p11->C_Initialize(&args);
  EXPECT_RV(rv, CKR_OK, "init(full callbacks)");
  EXPECT_TRUE(g_mu_created >= 1, "mutex created via callback");
  {
    CK_ULONG n = 0;
    rv = p11->C_GetSlotList(0, NULL, &n);
    EXPECT_RV(rv, CKR_OK, "call under callback locking");
  }
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "finalize destroys callback mutex");
  EXPECT_TRUE(g_mu_destroyed == g_mu_created && g_mu_created >= 1,
              "create/destroy balanced");
  EXPECT_TRUE(g_mu_locked >= 1 && g_mu_unlocked >= 1,
              "lock/unlock callbacks invoked");

  /* 3. Full callbacks without OS-locking flag: also fine. */
  mu_reset();
  memset(&args, 0, sizeof(args));
  args.CreateMutex = mu_create;
  args.DestroyMutex = mu_destroy;
  args.LockMutex = mu_lock;
  args.UnlockMutex = mu_unlock;
  args.flags = 0;
  rv = p11->C_Initialize(&args);
  EXPECT_RV(rv, CKR_OK, "init(callbacks, no OS flag)");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "finalize (no OS flag)");
  EXPECT_TRUE(g_mu_destroyed == g_mu_created && g_mu_created >= 1,
              "balanced without OS flag");

  /* 4. Partial callbacks rejected. */
  memset(&args, 0, sizeof(args));
  args.CreateMutex = mu_create;
  rv = p11->C_Initialize(&args);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "partial callbacks rejected");

  /* 5. Non-NULL reserved rejected. */
  memset(&args, 0, sizeof(args));
  args.pReserved = (void *)0x1;
  rv = p11->C_Initialize(&args);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "non-NULL pReserved rejected");

  /* 6. Thread prohibition refused (explicit RTS limitation), no poisoning. */
  memset(&args, 0, sizeof(args));
  args.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
  rv = p11->C_Initialize(&args);
  EXPECT_RV(rv, CKR_NEED_TO_CREATE_THREADS, "cant-create-threads refused");
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "init works after refusal");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "finalize after refusal");

  /* 7. Mutex-creation failure rolls back cleanly (CKR_CANT_LOCK). */
  memset(&args, 0, sizeof(args));
  args.CreateMutex = mu_fail_create;
  args.DestroyMutex = mu_destroy;
  args.LockMutex = mu_lock;
  args.UnlockMutex = mu_unlock;
  args.flags = 0;
  rv = p11->C_Initialize(&args);
  EXPECT_RV(rv, CKR_CANT_LOCK, "failing CreateMutex rolls back");
  {
    CK_ULONG n = 0xDEADu;
    rv = p11->C_GetSlotList(0, NULL, &n);
    EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "no interval after rollback");
  }
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "init works after rollback");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "finalize after rollback");

  /* 8. Finalize with non-NULL reserved rejected. */
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "init for finalize-args probe");
  rv = p11->C_Finalize((void *)0x1);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "finalize reserved rejected");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "finalize after reserved probe");

  CASE_END("A05");
}

/* Digest slice (routed to the real engine; the TEMPORARY adapter
 * is gone, so every call below takes a real session handle). */
static const unsigned char KAT_SHA1_ABC[20] = {
  0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
  0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
};
static const unsigned char KAT_EMPTY[32] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
  0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
  0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
static const unsigned char KAT_ABC[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
  0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
  0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
static const unsigned char KAT_448[32] = {
  0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
  0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff,
  0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

static void do_kat(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE sess,
                   const char *label, const unsigned char *msg,
                   CK_ULONG msg_len, const unsigned char *want) {
  CK_RV rv;
  CK_MECHANISM mech;
  canary_digest_t c;
  CK_ULONG len;

  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  rv = p11->C_DigestInit(sess, &mech);
  EXPECT_RV(rv, CKR_OK, label);
  c.pre = CANARY_MAGIC;
  c.post = CANARY_MAGIC;
  len = sizeof(c.digest);
  rv = p11->C_Digest(sess, (CK_BYTE_PTR)msg, msg_len, c.digest, &len);
  EXPECT_RV(rv, CKR_OK, label);
  EXPECT_TRUE(len == 32, label);
  EXPECT_TRUE(memcmp(c.digest, want, 32) == 0, label);
  EXPECT_TRUE(c.pre == CANARY_MAGIC && c.post == CANARY_MAGIC, label);
}

static void case_sha(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  CK_MECHANISM mech;
  CK_ULONG len;
  unsigned char buf[32];
  CK_SESSION_HANDLE sess = 0;
  static const char msg448[] =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  case_mark_start();
  CASE_BEGIN("SHA", "digest KATs (routed engine)");

  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "sha init");
  rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                          NULL, &sess);
  EXPECT_RV(rv, CKR_OK, "sha open session");
  EXPECT_TRUE(sess != 0, "sha session handle valid");

  /* Mechanism advertisement (full catalog, not one row). */
  {
    CK_ULONG n = 0;
    CK_MECHANISM_TYPE ms[ROUTED_MECH_COUNT];
    CK_MECHANISM_INFO mi;
    int i, found = 0;
    rv = p11->C_GetMechanismList(0, NULL, &n);
    EXPECT_RV(rv, CKR_OK, "mech count query");
    EXPECT_TRUE(n == ROUTED_MECH_COUNT, "mechanism count");
    n = 1;
    rv = p11->C_GetMechanismList(0, ms, &n);
    EXPECT_RV(rv, CKR_BUFFER_TOO_SMALL, "mech list short fill");
    EXPECT_TRUE(n == ROUTED_MECH_COUNT, "short fill reports count");
    n = ROUTED_MECH_COUNT;
    rv = p11->C_GetMechanismList(0, ms, &n);
    EXPECT_RV(rv, CKR_OK, "mech list fill");
    EXPECT_TRUE(n == ROUTED_MECH_COUNT, "fill reports count");
    for (i = 0; i < (int)n; i++) {
      if (ms[i] == CKM_SHA256) {
        found = 1;
      }
    }
    EXPECT_TRUE(found, "catalog contains CKM_SHA256");
    rv = p11->C_GetMechanismList(99, NULL, &n);
    EXPECT_RV(rv, CKR_SLOT_ID_INVALID, "mech list bad slot");
    rv = p11->C_GetMechanismInfo(0, CKM_SHA256, &mi);
    EXPECT_RV(rv, CKR_OK, "mech info");
    EXPECT_TRUE(mi.ulMinKeySize == 0 && mi.ulMaxKeySize == 0, "no key sizes");
    EXPECT_TRUE((mi.flags & CKF_DIGEST) != 0, "CKF_DIGEST set");
    rv = p11->C_GetMechanismInfo(0, CKM_SHA_1, &mi);
    EXPECT_RV(rv, CKR_OK, "mech info admits SHA-1");
    EXPECT_TRUE((mi.flags & CKF_DIGEST) != 0, "SHA-1 CKF_DIGEST set");
  }

  /* SHA-1 is engine-supported: init succeeds, and the
   * one-shot consumes the op, leaving clean state for the negatives. */
  mech.mechanism = CKM_SHA_1;
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  rv = p11->C_DigestInit(sess, &mech);
  EXPECT_RV(rv, CKR_OK, "digest init admits SHA-1");
  len = sizeof(buf);
  rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
  EXPECT_RV(rv, CKR_OK, "SHA-1 one-shot ok");
  EXPECT_TRUE(len == 20, "SHA-1 length");
  EXPECT_TRUE(memcmp(buf, KAT_SHA1_ABC, 20) == 0, "SHA-1 abc value");

  /* Negative negotiation. */
  rv = p11->C_DigestInit(sess, NULL);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "digest init NULL mech");
  {
    /* The engine recipe requires empty digest params (checkMechParams):
     * a stray param byte is ARGUMENTS_BAD, not PARAM_INVALID (the legacy
     * adapter's code). Same pin lives in consumer_roundtrip. */
    CK_BYTE param = 0;
    mech.mechanism = CKM_SHA256;
    mech.pParameter = &param;
    mech.ulParameterLen = 1;
    rv = p11->C_DigestInit(sess, &mech);
    EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "digest init rejects stray param");
  }
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  rv = p11->C_DigestInit(DUMMY_SESSION, &mech);
  EXPECT_RV(rv, CKR_SESSION_HANDLE_INVALID, "digest init dummy handle");
  len = sizeof(buf);
  rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
  EXPECT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "digest without init");

  /* Size-query and too-small do not consume the operation. */
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  rv = p11->C_DigestInit(sess, &mech);
  EXPECT_RV(rv, CKR_OK, "digest init");
  rv = p11->C_DigestInit(sess, &mech);
  EXPECT_RV(rv, CKR_OPERATION_ACTIVE, "second init while active");
  len = 0xDEADu;
  rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, NULL, &len);
  EXPECT_RV(rv, CKR_OK, "digest size query");
  EXPECT_TRUE(len == 32, "size query length");
  {
    unsigned char small[16];
    len = sizeof(small);
    rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, small, &len);
    EXPECT_RV(rv, CKR_BUFFER_TOO_SMALL, "digest too-small");
    EXPECT_TRUE(len == 32, "too-small reports length");
  }
  len = sizeof(buf);
  rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
  EXPECT_RV(rv, CKR_OK, "digest retry after probes");
  EXPECT_TRUE(memcmp(buf, KAT_ABC, 32) == 0, "digest abc value");
  rv = p11->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf, &len);
  EXPECT_RV(rv, CKR_OPERATION_NOT_INITIALIZED, "one-shot consumed");
  /* Routed C_Digest validates the length pointer before op state, so a
   * NULL pulDigestLen is ARGUMENTS_BAD even with no live op. */
  rv = p11->C_Digest(sess, NULL, 0, NULL, NULL);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "null length pointer is args-first");

  /* Known-answer vectors (FIPS 180-4). */
  do_kat(p11, sess, "KAT empty", (const unsigned char *)"", 0, KAT_EMPTY);
  do_kat(p11, sess, "KAT abc", (const unsigned char *)"abc", 3, KAT_ABC);
  do_kat(p11, sess, "KAT 448-bit", (const unsigned char *)msg448,
         (CK_ULONG)strlen(msg448), KAT_448);

  rv = p11->C_CloseSession(sess);
  EXPECT_RV(rv, CKR_OK, "sha close session");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "sha finalize");
  CASE_END("SHA");
}

/* Lifecycle spot-checks: pre-init sees no state; post-init, formerly
 * stubbed calls route and validate slot/args. The legacy
 * parallel pair stays at FUNCTION_NOT_PARALLEL. */
static void case_stub(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  case_mark_start();
  CASE_BEGIN("STB", "lifecycle + routed token-info (slot/args/label)");
  rv = p11->C_GetTokenInfo(0, NULL);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "token-info pre-init");
  /* Liveness beats capability even on stubs (garbage
   * args, pre-init interval). */
  rv = p11->C_InitToken(99, NULL, 0xFFFFFFFFu, NULL);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "stub-beats-args pre-init");
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "stub init");
  rv = p11->C_GetTokenInfo(0, NULL);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "token-info NULL buffer");
  rv = p11->C_GetTokenInfo(99, NULL);
  EXPECT_RV(rv, CKR_SLOT_ID_INVALID, "token-info bad slot first");
  /* CK_TOKEN_INFO stays opaque in this harness; the provider writes 208
   * bytes (pinned by layout_240) with the label at offset 0, so an
   * oversized byte buffer reads the provisioned label with no layout. */
  {
    unsigned char raw[256];
    memset(raw, 0xA5, sizeof(raw));
    rv = p11->C_GetTokenInfo(0, (CK_TOKEN_INFO_PTR)raw);
    EXPECT_RV(rv, CKR_OK, "token-info routed ok");
    EXPECT_TRUE(memcmp(raw, "haskoki-demo", 12) == 0,
                "token-info provisioned label");
  }
  rv = p11->C_GetFunctionStatus(DUMMY_SESSION);
  EXPECT_RV(rv, CKR_FUNCTION_NOT_PARALLEL, "legacy parallel status");
  rv = p11->C_CancelFunction(DUMMY_SESSION);
  EXPECT_RV(rv, CKR_FUNCTION_NOT_PARALLEL, "legacy parallel cancel");
  /* stub-beats-args — garbage/NULL args to stubs yield
   * the stub code, never an argument error (uniform stub-first). */
  rv = p11->C_InitToken(99, NULL, 0xFFFFFFFFu, NULL);
  EXPECT_RV(rv, CKR_FUNCTION_NOT_SUPPORTED, "stub-beats-args init-token");
  rv = p11->C_SetPIN(0xFFFFFFFFu, NULL, 0, NULL, 0);
  EXPECT_RV(rv, CKR_FUNCTION_NOT_SUPPORTED, "stub-beats-args set-pin");
  rv = p11->C_SignRecoverInit(DUMMY_SESSION, NULL, 0);
  EXPECT_RV(rv, CKR_FUNCTION_NOT_SUPPORTED, "stub-beats-args sign-recover");
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "stub finalize");
  CASE_END("STB");
}

/* A06, part 1: fork child must fail safe without entering Haskell. */
static void case_a06_fork(CK_FUNCTION_LIST_PTR p11) {
  CK_RV rv;
  pid_t pid;
  int status = 0;
  case_mark_start();
  CASE_BEGIN("A06a", "fork-child safe failure (no Haskell entry)");
  rv = p11->C_Initialize(NULL);
  EXPECT_RV(rv, CKR_OK, "fork test init");
  fflush(stdout);
  pid = fork();
  if (pid < 0) {
    EXPECT_TRUE(0, "fork succeeded");
    p11->C_Finalize(NULL);
    CASE_END("A06a");
    return;
  }
  if (pid == 0) {
    /* Child: only async-signal-safe + documented-safe calls; _exit. */
    int fails = 0;
    CK_ULONG n = 0;
    CK_INFO info;
    alarm(10);
    if (p11->C_GetSlotList(0, NULL, &n) != CKR_CRYPTOKI_NOT_INITIALIZED) {
      fails |= 1;
    }
    if (p11->C_GetInfo(&info) != CKR_OK) {
      fails |= 2;
    }
    if (p11->C_DigestInit(DUMMY_SESSION, NULL) !=
        CKR_CRYPTOKI_NOT_INITIALIZED) {
      fails |= 4;
    }
    if (p11->C_Initialize(NULL) != CKR_GENERAL_ERROR) {
      fails |= 8;
    }
    if (p11->C_Finalize(NULL) != CKR_CRYPTOKI_NOT_INITIALIZED) {
      fails |= 16;
    }
    /* Crypto entries gate on the boot-PID check first
     * (live_interval precedes argument dereference), so NULL
     * mechanisms refuse cleanly without entering Haskell. */
    if (p11->C_SignInit(DUMMY_SESSION, NULL, 0) !=
        CKR_CRYPTOKI_NOT_INITIALIZED) {
      fails |= 32;
    }
    if (p11->C_EncryptInit(DUMMY_SESSION, NULL, 0) !=
        CKR_CRYPTOKI_NOT_INITIALIZED) {
      fails |= 64;
    }
    _exit(fails);
  }
  if (waitpid(pid, &status, 0) < 0) {
    EXPECT_TRUE(0, "waitpid");
  } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    char label[64];
    snprintf(label, sizeof(label), "child clean (status 0x%x)", status);
    EXPECT_TRUE(0, label);
  } else {
    g_checks++;
  }
  /* Parent unaffected. */
  {
    CK_ULONG n = 0;
    rv = p11->C_GetSlotList(0, NULL, &n);
    EXPECT_RV(rv, CKR_OK, "parent still initialized");
  }
  rv = p11->C_Finalize(NULL);
  EXPECT_RV(rv, CKR_OK, "fork test finalize");
  CASE_END("A06a");
}

/* T00D: direct symbols. Calls haskoki_initialize /
 * haskoki_finalize / haskoki_get_slot_list straight through dlsym and
 * asserts the full return-code matrix: open/double-open, pre/post
 * gating, size-query, short-buffer, NULL count, close/double-close.
 * Runs after A03 (RTS up, provider flag clear) and is balanced (ends
 * finalized), so later cases see a clean slate. The direct slot list
 * is frozen (token-present reports zero) while the routed path
 * evolved; both contracts are pinned here and in A03.
 * Run-to-run logs of this case must be byte-identical. */
static void case_t00_direct(void *handle) {
  uint64_t (*direct_init)(void);
  uint64_t (*direct_fini)(void);
  uint64_t (*direct_slots)(uint8_t, uint64_t *, uint64_t *);
  uint64_t rv, n, slot;
  case_mark_start();
  CASE_BEGIN("T00D", "direct symbols (init/finalize/slot-list)");
  direct_init = (uint64_t (*)(void))dlsym(handle, "haskoki_initialize");
  EXPECT_TRUE(direct_init != NULL, "dlsym haskoki_initialize");
  direct_fini = (uint64_t (*)(void))dlsym(handle, "haskoki_finalize");
  EXPECT_TRUE(direct_fini != NULL, "dlsym haskoki_finalize");
  direct_slots =
      (uint64_t (*)(uint8_t, uint64_t *, uint64_t *))dlsym(handle,
                                                           "haskoki_get_slot_list");
  EXPECT_TRUE(direct_slots != NULL, "dlsym haskoki_get_slot_list");
  if (direct_init == NULL || direct_fini == NULL || direct_slots == NULL) {
    CASE_END("T00D");
    return;
  }
  /* Fresh (post-A03 finalize): finalize-without-init refuses. */
  rv = direct_fini();
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "direct finalize without init");
  /* Pre-init slot list gated (liveness checked before arguments). */
  n = 0xDEADu;
  rv = direct_slots(0, NULL, &n);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "direct slots pre-init");
  slot = 0xBEEFu;
  rv = direct_slots(0, &slot, NULL);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "direct null count pre-init");
  /* Open; second open rejected. */
  rv = direct_init();
  EXPECT_RV(rv, CKR_OK, "direct init");
  rv = direct_init();
  EXPECT_RV(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED, "direct double init");
  /* Size-query contract. */
  n = 0;
  rv = direct_slots(0, NULL, &n);
  EXPECT_RV(rv, CKR_OK, "direct count query");
  EXPECT_TRUE(n == 1, "direct one slot");
  n = 1;
  slot = 0xBEEFu;
  rv = direct_slots(0, &slot, &n);
  EXPECT_RV(rv, CKR_OK, "direct list fill");
  EXPECT_TRUE(slot == 0 && n == 1, "direct slot id 0");
  /* Token-present direct path reports zero (frozen direct contract). */
  n = 0xDEADu;
  rv = direct_slots(1, NULL, &n);
  EXPECT_RV(rv, CKR_OK, "direct token-present count");
  EXPECT_TRUE(n == 0, "direct token-present zero");
  /* Short buffer reports the count and writes nothing. */
  n = 0;
  slot = 0xBEEFu;
  rv = direct_slots(0, &slot, &n);
  EXPECT_RV(rv, CKR_BUFFER_TOO_SMALL, "direct too-small");
  EXPECT_TRUE(n == 1, "direct too-small count");
  EXPECT_TRUE(slot == 0xBEEFu, "direct too-small writes nothing");
  /* NULL count once live. */
  rv = direct_slots(0, &slot, NULL);
  EXPECT_RV(rv, CKR_ARGUMENTS_BAD, "direct null count");
  /* Close, balanced; everything gated again. */
  rv = direct_fini();
  EXPECT_RV(rv, CKR_OK, "direct finalize");
  rv = direct_fini();
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "direct double finalize");
  n = 0xDEADu;
  rv = direct_slots(0, NULL, &n);
  EXPECT_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "direct slots post-finalize");
  CASE_END("T00D");
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList sym;
  CK_FUNCTION_LIST_PTR p11 = NULL;
  CK_RV rv;
  const char *soname;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  soname = argv[1];

  /* RTLD_NOW: fail fast if the module is not self-contained at load. */
  handle = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    fprintf(stderr, "FAIL dlopen(%s): %s\n", soname, dlerror());
    return 1;
  }
  dlerror();
  sym = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (sym == NULL) {
    fprintf(stderr, "FAIL dlsym(C_GetFunctionList): %s\n", dlerror());
    dlclose(handle);
    return 1;
  }
  g_checks += 2; /* dlopen + dlsym */
  printf("LOAD: dlopen+dlsym OK (%s)\n", soname);

  rv = sym(&p11);
  if (rv != CKR_OK || p11 == NULL) {
    fprintf(stderr, "FAIL initial C_GetFunctionList: 0x%lx\n",
            (unsigned long)rv);
    dlclose(handle);
    return 1;
  }
  g_checks++;

  case_a01(p11);
  case_a02(p11);
  case_a03(p11);
  case_t00_direct(handle);
  case_a05(p11);
  case_a04(p11);
  case_sha(p11);
  case_stub(p11);
  case_a06_fork(p11);

  /* A06, part 2: dlclose/reopen retention (linker pinning strategy). */
  {
    CK_FUNCTION_LIST_PTR p2 = NULL;
    CK_C_GetFunctionList sym2;
    void *h2;
    CK_ULONG n;
    case_mark_start();
    CASE_BEGIN("A06b", "dlclose/reopen retention (pinning)");
    rv = p11->C_Initialize(NULL);
    EXPECT_RV(rv, CKR_OK, "pin init");
    if (dlclose(handle) != 0) {
      EXPECT_TRUE(0, "dlclose ok");
    } else {
      g_checks++;
    }
    handle = NULL;
    h2 = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
    EXPECT_TRUE(h2 != NULL, "reopen ok");
    if (h2 == NULL) {
      printf("  dlopen error: %s\n", dlerror());
      CASE_END("A06b");
    } else {
      handle = h2;
      sym2 = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
      EXPECT_TRUE(sym2 != NULL, "re-dlsym ok");
      if (sym2 != NULL) {
        rv = sym2(&p2);
        EXPECT_RV(rv, CKR_OK, "re-discovery");
        /* State retained across close/reopen: still initialized. */
        n = 0;
        rv = p2->C_GetSlotList(0, NULL, &n);
        EXPECT_RV(rv, CKR_OK, "retained interval");
        EXPECT_TRUE(n == 1, "retained slot count");
        p11 = p2;
        rv = p11->C_Finalize(NULL);
        EXPECT_RV(rv, CKR_OK, "finalize after reopen");
        rv = p11->C_Initialize(NULL);
        EXPECT_RV(rv, CKR_OK, "fresh init after reopen");
        rv = p11->C_Finalize(NULL);
        EXPECT_RV(rv, CKR_OK, "finalize fresh interval");
      }
      CASE_END("A06b");
    }
  }

  if (handle != NULL) {
    dlclose(handle);
  }
  printf("SUMMARY: %d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
