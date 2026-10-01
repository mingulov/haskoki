/* cbits/function_tables.c — legacy 2.40 function table + original slice.
 *
 * Original scope: discovery (C_GetFunctionList, usable before C_Initialize
 * without entering Haskell), lifecycle (C_Initialize/C_Finalize via the
 * RTS bootstrap + Haskell provider state), minimal metadata
 * (C_GetInfo/C_GetSlotList/C_GetMechanismList/C_GetMechanismInfo), and
 * one SHA-256 one-shot operation (TEMPORARY adapter below; replaced by
 * the engine contract).
 *
 * Contract order (documented choices):
 *  - Transition calls (C_Initialize/C_Finalize) validate arguments
 *    first. In particular CKF_LIBRARY_CANT_CREATE_OS_THREADS is refused
 *    with CKR_NEED_TO_CREATE_THREADS BEFORE the RTS starts: the
 *    threaded RTS cannot honor a no-thread host (03 §7 limitation).
 *  - Stateful calls check lifecycle/state first (fork-child and
 *    not-initialized dominate argument errors), then arguments.
 *  - Non-slice entries are real functions (never NULL) returning
 *    CKR_CRYPTOKI_NOT_INITIALIZED pre-init, CKR_FUNCTION_NOT_SUPPORTED
 *    once live — except legacy C_GetFunctionStatus/C_CancelFunction,
 *    which report CKR_FUNCTION_NOT_PARALLEL, and C_WaitForSlotEvent,
 *    which is real (waitable slot events, no state lock
 *    held across the blocking call).
 *  - Fork children (PID != boot PID after the RTS started) fail safe:
 *    stateful calls see CKR_CRYPTOKI_NOT_INITIALIZED and C_Initialize
 *    sees CKR_GENERAL_ERROR, all without entering Haskell. Pure
 *    discovery (C_GetFunctionList/C_GetInfo) stays available.
 *  - Session handles were ignored by the original digest slice
 *    (session scoping arrived later). The direct surface exposes
 *    one slot (id 0) and no token model (token-present queries
 *    report zero slots).
 *  - Finalization is not safe against concurrent in-flight calls
 *    (waits out lock holders, but a fresh entrant racing finalize is
 *    unprotected); async admission leases arrived later. The harness
 *    joins all threads before finalizing.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Generated 2.40 order + shared probe/internal API. Neither
 * header defines Cryptoki types, so they coexist with the local
 * mirror below. */
#include "abi_generated.h"
#include "abi_probe.h"

/* Standard-surface instance root (stdint-only: no Cryptoki
 * types, so it coexists with the mirror too). */
#include "standard_surface.h"

/* RTS bootstrap API (cbits/rts_bootstrap.c). */
extern int haskoki_rts_ensure(void);
extern int haskoki_c_entry_ok(void);

/* Direct surface (C-owned, defined in standard_surface.c).
 * Same symbols and signatures the Haskell exports had; declared
 * unconditionally (no stub header: there is no Haskell side left). */
#include <stdint.h>
extern uint64_t haskoki_initialize(void);
extern uint64_t haskoki_finalize(void);
extern uint64_t haskoki_get_slot_list(uint8_t token_present,
                                      uint64_t *p_slot_list,
                                      uint64_t *p_count);

/* Standard-surface exports (ffi/Haskoki/FFI/Standard.hs): the
 * generated Standard_stub.h when available, else manual
 * declarations (HsWord64/HsWord8/HsPtr). */
#if defined(__has_include)
#if __has_include("Haskoki/FFI/Standard_stub.h")
#include "Haskoki/FFI/Standard_stub.h"
#define HASKOKI_HAVE_STD_STUB_H 1
#elif __has_include("Haskoki_FFI_Standard_stub.h")
#include "Haskoki_FFI_Standard_stub.h"
#define HASKOKI_HAVE_STD_STUB_H 1
#endif
#endif
#ifndef HASKOKI_HAVE_STD_STUB_H
#include <stdint.h>
extern void haskoki_std_close(void *instance);
extern uint64_t haskoki_std_get_slot_list(void *instance,
                                          uint8_t token_present,
                                          uint64_t *p_slot_list,
                                          uint64_t *p_count);
#endif

/* Control instance root (cbits/control_entry.c): one owned ops instance
 * per init interval, shared by C_WaitForSlotEvent and
 * HASKOKI_Control. */
extern void *haskoki_instance_open_fresh(void);
extern void haskoki_instance_close(void *instance);
extern void haskoki_instance_install(void *instance);
extern void haskoki_instance_shutdown(void);
extern unsigned long haskoki_instance_wait_for_slot_event(unsigned long flags,
                                                        unsigned long *p_slot);

/* ================= local cryptoki subset (BEGIN) =================
 * Provider-local mirror of the PKCS#11 v2.40 legacy interface.
 * Verified against the byte-locked 2.40 headers by the layout_240
 * probes; still the legacy serving path (the versioned 3.x tables in
 * exports.c are generated from the locked headers).
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
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK 0x00000002UL
#define CKF_DONT_BLOCK 0x00000001UL

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

/* ---------- provider interval state ---------- */

/* C-side mirror of the Haskell interval flag; set only on
 * Haskell-confirmed transitions (checked before every stateful call). */
static atomic_int g_initialized = ATOMIC_VAR_INIT(0);

/* Serializes C_Initialize/C_Finalize bodies (never held across
 * negotiated-mutex operations except the init handshake itself). */
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;

/* Negotiated application mutex callbacks for the live interval (03 §7:
 * they govern the provider's exposed locking contract, not GHC-internal
 * synchronization). When absent, the internal mutex is used. */
static CK_C_INITIALIZE_ARGS g_cb;
static CK_VOID_PTR g_negotiated_mu = NULL;
static int g_have_negotiated = 0;
static pthread_mutex_t g_internal_mu = PTHREAD_MUTEX_INITIALIZER;

/* The same bodies with wider linkage, so the routed bodies
 * in cbits/standard_surface.c (which declare
 * haskoki_state_lock/unlock) honor the negotiated-mutex contract.
 * In-TU callers keep the short static wrappers. */
CK_RV haskoki_state_lock(void) {
  if (g_have_negotiated) {
    return g_cb.LockMutex(g_negotiated_mu);
  }
  return pthread_mutex_lock(&g_internal_mu) == 0 ? CKR_OK : CKR_CANT_LOCK;
}

CK_RV haskoki_state_unlock(void) {
  if (g_have_negotiated) {
    return g_cb.UnlockMutex(g_negotiated_mu);
  }
  return pthread_mutex_unlock(&g_internal_mu) == 0 ? CKR_OK : CKR_CANT_LOCK;
}

static CK_RV state_lock(void) {
  return haskoki_state_lock();
}

static CK_RV state_unlock(void) {
  return haskoki_state_unlock();
}

static int live_interval(void) {
  return haskoki_c_entry_ok() && atomic_load(&g_initialized);
}

/* ---------- slice implementations ---------- */

static CK_RV on_Initialize(CK_VOID_PTR pInitArgs) {
  CK_C_INITIALIZE_ARGS_PTR a = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
  CK_RV hv;
  int use_callbacks = 0;

  /* Fork child: the RTS image is inherited; never (re)bootstrap here. */
  if (!haskoki_c_entry_ok()) {
    return CKR_GENERAL_ERROR;
  }
  /* Argument validation precedes any state change or RTS start. */
  if (a != NULL) {
    int ncb;
    if (a->pReserved != NULL) {
      return CKR_ARGUMENTS_BAD;
    }
    if ((a->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0) {
      /* Explicit limitation: the threaded RTS needs OS threads. */
      return CKR_NEED_TO_CREATE_THREADS;
    }
    ncb = (a->CreateMutex != NULL) + (a->DestroyMutex != NULL) +
          (a->LockMutex != NULL) + (a->UnlockMutex != NULL);
    if (ncb != 0 && ncb != 4) {
      return CKR_ARGUMENTS_BAD;
    }
    use_callbacks = (ncb == 4);
  }

  pthread_mutex_lock(&g_init_lock);
  if (haskoki_rts_ensure() != 0) {
    pthread_mutex_unlock(&g_init_lock);
    return CKR_GENERAL_ERROR;
  }
  hv = (CK_RV)haskoki_initialize();
  if (hv != CKR_OK) {
    pthread_mutex_unlock(&g_init_lock);
    return hv;
  }
  /* Build both owners unpublished. Standard borrows this cell's resolved
   * config/hub and binds its Haskell owner before returning. Only after mutex
   * adoption can either root be installed. Rollback closes local owners once. */
  {
    void *inst = haskoki_instance_open_fresh();
    void *std = NULL;
    CK_RV failure = CKR_GENERAL_ERROR;
    if (inst == NULL) {
      goto acquisition_failed;
    }
    std = haskoki_std_open_fresh(inst);
    if (std == NULL) {
      goto acquisition_failed;
    }
    if (use_callbacks) {
      CK_VOID_PTR m = NULL;
      CK_RV created = a->CreateMutex(&m);
      if (created != CKR_OK || m == NULL) {
        /* A callback may supply a resource even when it refuses creation. */
        if (m != NULL) {
          (void)a->DestroyMutex(m);
        }
        failure = CKR_CANT_LOCK;
        goto acquisition_failed;
      }
      g_cb = *a;
      g_negotiated_mu = m;
      g_have_negotiated = 1;
    }
    haskoki_std_install(std);
    haskoki_instance_install(inst);
    goto acquisition_ready;

  acquisition_failed:
    if (std != NULL) {
      /* Haskell clears its bound owner before releasing native resources. */
      haskoki_std_close(std);
    }
    if (inst != NULL) {
      haskoki_instance_close(inst);
    }
    (void)haskoki_finalize();
    pthread_mutex_unlock(&g_init_lock);
    return failure;
  }
acquisition_ready:
  atomic_store(&g_initialized, 1);
  pthread_mutex_unlock(&g_init_lock);
  return CKR_OK;
}

static CK_RV on_Finalize(CK_VOID_PTR pReserved) {
  CK_RV hv;
  CK_RV lr;
  if (pReserved != NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  /* Fork child or never-booted image: no live provider here, and no
   * Haskell entry. Ends nothing; notably never stops the RTS. */
  if (!haskoki_c_entry_ok()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  pthread_mutex_lock(&g_init_lock);
  if (!atomic_load(&g_initialized)) {
    pthread_mutex_unlock(&g_init_lock);
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* Liveness-first teardown: clear liveness FIRST so fresh
   * entrants fail fast on live_interval(), then take-and-hold the
   * state lock across the whole teardown below. In-flight holders
   * drain (the acquisition waits them out); stale entrants that
   * passed the liveness gate block, then resolve a NULL instance
   * under the lock and report NOT_INITIALIZED. Either way no
   * entrant observes dead Haskell state. Lock order stays globally
   * g_init_lock-then-state_lock (entries take only the latter), so
   * this cannot deadlock; C_WaitForSlotEvent still never holds the
   * state lock while blocking (on_WaitForSlotEvent below, plus the
   * control_entry.c discipline note), so no waiter strands us here. */
  atomic_store(&g_initialized, 0);
  lr = state_lock();
  if (lr != CKR_OK) {
    /* Negotiated-mutex refusal: restore liveness and fail loudly
     * (retryable) rather than tear down under in-flight holders. */
    atomic_store(&g_initialized, 1);
    pthread_mutex_unlock(&g_init_lock);
    return lr;
  }
  /* Shut the standard-surface instance first (closes the
   * backend and the process store while everything is live). */
  haskoki_std_shutdown();
  /* End the Haskell interval (never stops the RTS). */
  hv = (CK_RV)haskoki_finalize();
  /* Shut the ops instance (finalizes the event queue FIRST, so
   * every blocked slot-event waiter wakes with the source-correct
   * code instead of stranding). Fast and nonblocking: safe here. */
  haskoki_instance_shutdown();
  /* Tear down interval locking while still holding the state lock:
   * no entrant can be inside (they all serialize through it). */
  if (g_have_negotiated) {
    CK_VOID_PTR m = g_negotiated_mu;
    g_negotiated_mu = NULL;
    g_have_negotiated = 0;
    (void)g_cb.UnlockMutex(m);
    (void)g_cb.DestroyMutex(m);
    memset(&g_cb, 0, sizeof(g_cb));
  } else {
    (void)state_unlock();
  }
  pthread_mutex_unlock(&g_init_lock);
  return hv;
}

static CK_RV on_GetInfo(CK_INFO_PTR pInfo) {
  static const char kManu[] = "haskoki contributors";
  static const char kDesc[] = "haskoki PKCS#11 demo";
  CK_INFO tmp;
  if (pInfo == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  /* Pure static metadata: callable before C_Initialize and after
   * C_Finalize, without entering Haskell. */
  /* Cryptoki-version ruling (spec-verified, kept at {2,40} on every table):
   * OASIS PKCS#11 Base v3.0 §5.4.3/CK_INFO says "For libraries
   * written to this document, the value of cryptokiVersion should
   * match the version of this specification" — SHOULD, not MUST —
   * while CK_FUNCTION_LIST_3_0.version "must be 3.0 at minimum"
   * (ours are exact 3.0/3.1/3.2, pinned). One shared C_GetInfo
   * serves the 2.40 table and the 3.x tables; reporting 3.x would
   * break 2.40 consumers (ecosystem-standard consumers gate on
   * major == 2), and 3.x discovery flows through
   * C_GetInterfaceList, not CK_INFO. Cross-table CK_INFO identity
   * is itself pinned deliberate behavior. Revisit criterion: if a
   * real 3.x consumer rejects CK_INFO.major == 2, adopt per-table
   * C_GetInfo versions (2.40 legacy / 3.x versioned) as an
   * intended behavior change with driver re-proof. */
  tmp.cryptokiVersion.major = 2;
  tmp.cryptokiVersion.minor = 40;
  memset(tmp.manufacturerID, ' ', sizeof(tmp.manufacturerID));
  memcpy(tmp.manufacturerID, kManu, sizeof(kManu) - 1);
  tmp.flags = 0;
  memset(tmp.libraryDescription, ' ', sizeof(tmp.libraryDescription));
  memcpy(tmp.libraryDescription, kDesc, sizeof(kDesc) - 1);
  /* libraryVersion tracks the shipped package (0.3.x at 0.3.0). */
  tmp.libraryVersion.major = 0;
  tmp.libraryVersion.minor = 3;
  memcpy(pInfo, &tmp, sizeof(tmp));
  return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

static CK_RV on_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                             CK_ULONG_PTR pulCount) {
  CK_RV lr, rv;
  void *inst;
  if (!live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  lr = state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  /* Revalidate the interval under the lock before reading its owner. */
  if (!live_interval()) {
    (void)state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* The export validates pointers and captures serving presence. */
  inst = haskoki_std_get();
  if (inst == NULL) {
    (void)state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_get_slot_list(inst, (uint8_t)tokenPresent,
                                        (uint64_t *)pSlotList,
                                        (uint64_t *)pulCount);
  (void)state_unlock();
  return rv;
}

/* Mechanism list/info moved to cbits/standard_surface.c
 * (std_GetMechanismList/std_GetMechanismInfo, served from the
 * generated real-tested catalog). */

/* Digest routed (std_DigestInit/std_Digest/
 * std_DigestUpdate/std_DigestFinal); the TEMPORARY adapter is gone. */

/* Keygen routed (std_GenerateKey/std_GenerateKeyPair). */

/* Sign/verify routed (std_SignInit/std_Sign/
 * std_SignUpdate/std_SignFinal/std_VerifyInit/std_Verify/
 * std_VerifyUpdate/std_VerifyFinal). Recover stays stubbed. */

/* Encrypt/decrypt routed (std_EncryptInit/std_Encrypt/
 * std_EncryptUpdate/std_EncryptFinal/std_DecryptInit/std_Decrypt/
 * std_DecryptUpdate/std_DecryptFinal). */

/* Random routed (std_GenerateRandom). SeedRandom stayed
 * honestly unsupported (then; routed just below). */
/* SeedRandom routed (std_SeedRandom); the stub is gone
 * (pre-init stays inside std_, as for every routed entry). */

/* Wrap/unwrap/derive routed (std_WrapKey/std_UnwrapKey/
 * std_DeriveKey: HKDF expand-only plus extract-and-expand,
 * opaque ECDH/DH/SHA-KDF/TLS-PRF arms). */

/* ---------- non-slice stubs ---------- */

/* Uniform stub rule (stub-first precedence, deliberate).
 * Every stub below voids its arguments and returns
 * liveness-then-capability: capability dominates argument errors
 * on every entry, because an unimplemented entry cannot act on
 * arguments and arg validation there would assert nothing. The
 * full per-entry chain is liveness (NOT_INITIALIZED outside the
 * live interval, even on stubs) -> capability (the stub code) ->
 * arguments never inspected. Masking note: bad args to a stub
 * yield the stub code (pinned by the STB stub-beats-args checks),
 * so argument bugs in stub CALLERS are invisible here by design;
 * routed entries keep liveness -> args -> behavior. Per-entry
 * setting (14 x stub_probe, 2 x stub_parallel): stub_InitToken,
 * stub_InitPIN, stub_SetPIN, stub_GetOperationState,
 * stub_SetOperationState, stub_GetObjectSize,
 * stub_SignRecoverInit,
 * stub_SignRecover, stub_VerifyRecoverInit, stub_VerifyRecover,
 * stub_DigestEncryptUpdate, stub_DecryptDigestUpdate,
 * stub_SignEncryptUpdate, stub_DecryptVerifyUpdate ->
 * stub_probe (NOT_INITIALIZED pre-init, NOT_SUPPORTED live);
 * stub_GetFunctionStatus, stub_CancelFunction -> stub_parallel
 * (legacy parallel pair: NOT_PARALLEL live). Revisit: when an
 * entry gains an implementation it leaves this table for the
 * routed shape. Structural uniformity is gated
 * (STUB-UNIFORM-LEGACY). */

static CK_RV stub_probe(void) {
  if (!live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV stub_parallel(void) {
  if (!live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  return CKR_FUNCTION_NOT_PARALLEL;
}

/* Slot/token info routed (std_GetSlotInfo/std_GetTokenInfo). */
static CK_RV stub_InitToken(CK_SLOT_ID s, CK_UTF8CHAR_PTR p, CK_ULONG n,
                             CK_UTF8CHAR_PTR l) {
  (void)s;
  (void)p;
  (void)n;
  (void)l;
  return stub_probe();
}
static CK_RV stub_InitPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR p, CK_ULONG n) {
  (void)h;
  (void)p;
  (void)n;
  return stub_probe();
}
static CK_RV stub_SetPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR o, CK_ULONG on,
                          CK_UTF8CHAR_PTR nw, CK_ULONG nn) {
  (void)h;
  (void)o;
  (void)on;
  (void)nw;
  (void)nn;
  return stub_probe();
}
/* Sessions routed (std_OpenSession/std_CloseSession/
 * std_CloseAllSessions/std_GetSessionInfo). */
static CK_RV stub_GetOperationState(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                    CK_ULONG_PTR n) {
  (void)h;
  (void)p;
  (void)n;
  return stub_probe();
}
static CK_RV stub_SetOperationState(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                    CK_ULONG n, CK_OBJECT_HANDLE e,
                                    CK_OBJECT_HANDLE a) {
  (void)h;
  (void)p;
  (void)n;
  (void)e;
  (void)a;
  return stub_probe();
}
/* Login/logout routed (std_Login/std_Logout). */
/* Create/copy/destroy/get-attribute/set-attribute/find routed
 * (std_CreateObject/std_CopyObject/std_DestroyObject/
 * std_GetAttributeValue/std_SetAttributeValue/std_FindObjectsInit/
 * std_FindObjects/std_FindObjectsFinal). GetObjectSize stays
 * honestly unsupported (no engine planner). */
static CK_RV stub_GetObjectSize(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
                                 CK_ULONG_PTR n) {
  (void)h;
  (void)o;
  (void)n;
  return stub_probe();
}
/* Digest update/final/key routed (std_DigestUpdate/
 * std_DigestKey/std_DigestFinal). */
static CK_RV stub_SignRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                                   CK_OBJECT_HANDLE k) {
  (void)h;
  (void)m;
  (void)k;
  return stub_probe();
}
static CK_RV stub_SignRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG n,
                               CK_BYTE_PTR q, CK_ULONG_PTR m) {
  (void)h;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  return stub_probe();
}
static CK_RV stub_VerifyRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                                     CK_OBJECT_HANDLE k) {
  (void)h;
  (void)m;
  (void)k;
  return stub_probe();
}
static CK_RV stub_VerifyRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG n,
                                 CK_BYTE_PTR q, CK_ULONG_PTR m) {
  (void)h;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  return stub_probe();
}
static CK_RV stub_DigestEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                       CK_ULONG n, CK_BYTE_PTR q,
                                       CK_ULONG_PTR m) {
  (void)h;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  return stub_probe();
}
static CK_RV stub_DecryptDigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                       CK_ULONG n, CK_BYTE_PTR q,
                                       CK_ULONG_PTR m) {
  (void)h;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  return stub_probe();
}
static CK_RV stub_SignEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                     CK_ULONG n, CK_BYTE_PTR q,
                                     CK_ULONG_PTR m) {
  (void)h;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  return stub_probe();
}
static CK_RV stub_DecryptVerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                       CK_ULONG n, CK_BYTE_PTR q,
                                       CK_ULONG_PTR m) {
  (void)h;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  return stub_probe();
}
static CK_RV stub_GetFunctionStatus(CK_SESSION_HANDLE h) {
  (void)h;
  return stub_parallel();
}
static CK_RV stub_CancelFunction(CK_SESSION_HANDLE h) {
  (void)h;
  return stub_parallel();
}
static CK_RV on_WaitForSlotEvent(CK_FLAGS f, CK_SLOT_ID_PTR p,
                                 CK_VOID_PTR r) {
  if (!live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  if (p == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  if (r != NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  if ((f & ~CKF_DONT_BLOCK) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  /* Blocking call: NEVER hold the C state lock across it (the
   * Haskell side owns instance synchronization); a waiter holding
   * the lock would serialize the module behind it. */
  return (CK_RV)haskoki_instance_wait_for_slot_event(f, p);
}

/* ---------- static table + exported discovery ---------- */

/* Routed bodies (defined with the pinned-header spellings in
 * cbits/standard_surface.c; declared here in the mirror
 * spelling — ABI-identical: unsigned long + pointers on LP64). */
extern CK_RV std_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
extern CK_RV std_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
extern CK_RV std_GetMechanismList(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE_PTR pMechanismList,
                                 CK_ULONG_PTR pulCount);
extern CK_RV std_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                                 CK_MECHANISM_INFO_PTR pInfo);
extern CK_RV std_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                             CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                             CK_SESSION_HANDLE_PTR phSession);
extern CK_RV std_CloseSession(CK_SESSION_HANDLE hSession);
extern CK_RV std_CloseAllSessions(CK_SLOT_ID slotID);
extern CK_RV std_GetSessionInfo(CK_SESSION_HANDLE hSession,
                               CK_SESSION_INFO_PTR pInfo);
extern CK_RV std_CreateObject(CK_SESSION_HANDLE hSession,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                              CK_OBJECT_HANDLE_PTR phObject);
extern CK_RV std_CopyObject(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                            CK_OBJECT_HANDLE_PTR phNewObject);
extern CK_RV std_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,
                                   CK_ULONG ulCount);
extern CK_RV std_DestroyObject(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject);
extern CK_RV std_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,
                                   CK_ULONG ulCount);
extern CK_RV std_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                 CK_ATTRIBUTE_PTR pTemplate,
                                 CK_ULONG ulCount);
extern CK_RV std_FindObjects(CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE_PTR phObject,
                             CK_ULONG ulMaxObjectCount,
                             CK_ULONG_PTR pulObjectCount);
extern CK_RV std_FindObjectsFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                       CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
extern CK_RV std_Logout(CK_SESSION_HANDLE hSession);
extern CK_RV std_DigestInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism);
extern CK_RV std_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                        CK_ULONG_PTR pulDigestLen);
extern CK_RV std_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                              CK_ULONG ulPartLen);
extern CK_RV std_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
extern CK_RV std_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                             CK_ULONG_PTR pulDigestLen);
extern CK_RV std_GenerateKey(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                             CK_OBJECT_HANDLE_PTR phKey);
extern CK_RV std_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_ULONG ulPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_ULONG ulPrivateKeyAttributeCount,
                                 CK_OBJECT_HANDLE_PTR phPublicKey,
                                 CK_OBJECT_HANDLE_PTR phPrivateKey);
extern CK_RV std_SignInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                      CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                      CK_ULONG_PTR pulSignatureLen);
extern CK_RV std_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                            CK_ULONG ulPartLen);
extern CK_RV std_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                           CK_ULONG_PTR pulSignatureLen);
extern CK_RV std_VerifyInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG ulSignatureLen);
extern CK_RV std_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                              CK_ULONG ulPartLen);
extern CK_RV std_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                             CK_ULONG ulSignatureLen);
extern CK_RV std_EncryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                         CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                         CK_ULONG_PTR pulEncryptedDataLen);
extern CK_RV std_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                               CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                               CK_ULONG_PTR pulEncryptedPartLen);
extern CK_RV std_EncryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastEncryptedPart,
                              CK_ULONG_PTR pulLastEncryptedPartLen);
extern CK_RV std_DecryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                         CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                         CK_ULONG_PTR pulDataLen);
extern CK_RV std_DecryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                               CK_ULONG_PTR pulPartLen);
extern CK_RV std_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                              CK_ULONG_PTR pulLastPartLen);
extern CK_RV std_GenerateRandom(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
extern CK_RV std_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                            CK_ULONG ulSeedLen);
extern CK_RV std_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                         CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
extern CK_RV std_UnwrapKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                           CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                           CK_ULONG ulAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey);
extern CK_RV std_DeriveKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey);

static struct CK_FUNCTION_LIST g_function_list = {
  .version = {2, 40},
  .C_Initialize = on_Initialize,
  .C_Finalize = on_Finalize,
  .C_GetInfo = on_GetInfo,
  .C_GetFunctionList = C_GetFunctionList,
  .C_GetSlotList = on_GetSlotList,
  .C_GetSlotInfo = std_GetSlotInfo,
  .C_GetTokenInfo = std_GetTokenInfo,
  .C_GetMechanismList = std_GetMechanismList,
  .C_GetMechanismInfo = std_GetMechanismInfo,
  .C_InitToken = stub_InitToken,
  .C_InitPIN = stub_InitPIN,
  .C_SetPIN = stub_SetPIN,
  .C_OpenSession = std_OpenSession,
  .C_CloseSession = std_CloseSession,
  .C_CloseAllSessions = std_CloseAllSessions,
  .C_GetSessionInfo = std_GetSessionInfo,
  .C_GetOperationState = stub_GetOperationState,
  .C_SetOperationState = stub_SetOperationState,
  .C_Login = std_Login,
  .C_Logout = std_Logout,
  .C_CreateObject = std_CreateObject,
  .C_CopyObject = std_CopyObject,
  .C_DestroyObject = std_DestroyObject,
  .C_GetObjectSize = stub_GetObjectSize,
  .C_GetAttributeValue = std_GetAttributeValue,
  .C_SetAttributeValue = std_SetAttributeValue,
  .C_FindObjectsInit = std_FindObjectsInit,
  .C_FindObjects = std_FindObjects,
  .C_FindObjectsFinal = std_FindObjectsFinal,
  .C_EncryptInit = std_EncryptInit,
  .C_Encrypt = std_Encrypt,
  .C_EncryptUpdate = std_EncryptUpdate,
  .C_EncryptFinal = std_EncryptFinal,
  .C_DecryptInit = std_DecryptInit,
  .C_Decrypt = std_Decrypt,
  .C_DecryptUpdate = std_DecryptUpdate,
  .C_DecryptFinal = std_DecryptFinal,
  .C_DigestInit = std_DigestInit,
  .C_Digest = std_Digest,
  .C_DigestUpdate = std_DigestUpdate,
  .C_DigestKey = std_DigestKey,
  .C_DigestFinal = std_DigestFinal,
  .C_SignInit = std_SignInit,
  .C_Sign = std_Sign,
  .C_SignUpdate = std_SignUpdate,
  .C_SignFinal = std_SignFinal,
  .C_SignRecoverInit = stub_SignRecoverInit,
  .C_SignRecover = stub_SignRecover,
  .C_VerifyInit = std_VerifyInit,
  .C_Verify = std_Verify,
  .C_VerifyUpdate = std_VerifyUpdate,
  .C_VerifyFinal = std_VerifyFinal,
  .C_VerifyRecoverInit = stub_VerifyRecoverInit,
  .C_VerifyRecover = stub_VerifyRecover,
  .C_DigestEncryptUpdate = stub_DigestEncryptUpdate,
  .C_DecryptDigestUpdate = stub_DecryptDigestUpdate,
  .C_SignEncryptUpdate = stub_SignEncryptUpdate,
  .C_DecryptVerifyUpdate = stub_DecryptVerifyUpdate,
  .C_GenerateKey = std_GenerateKey,
  .C_GenerateKeyPair = std_GenerateKeyPair,
  .C_WrapKey = std_WrapKey,
  .C_UnwrapKey = std_UnwrapKey,
  .C_DeriveKey = std_DeriveKey,
  .C_SeedRandom = std_SeedRandom,
  .C_GenerateRandom = std_GenerateRandom,
  .C_GetFunctionStatus = stub_GetFunctionStatus,
  .C_CancelFunction = stub_CancelFunction,
  .C_WaitForSlotEvent = on_WaitForSlotEvent,
};

/* Exported discovery entry: static table, no Haskell entry required,
 * callable before C_Initialize. */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  if (ppFunctionList == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  *ppFunctionList = &g_function_list;
  return CKR_OK;
}

/* ---------- provider-internal API (consumed by cbits/exports.c) ----------
 *
 * Publishes the legacy implementations by NAME (field designators below)
 * in generated 2.40 order, so the versioned tables re-home legacy behavior
 * without any cross-TU layout assumption. The fill runs under exports.c's
 * pthread_once (single-threaded); the cached array is write-once.
 */

size_t haskoki_legacy_fn_count(void) { return HASKOKI_ABI_COUNT_240; }

size_t haskoki_legacy_fns(haskoki_fn_t *out, size_t n) {
  static haskoki_fn_t cache[HASKOKI_ABI_COUNT_240];
  static int filled = 0;
  size_t i, k;
  if (out == NULL) {
    return 0;
  }
  if (!filled) {
    i = 0;
#define M(name) cache[i++] = (haskoki_fn_t)g_function_list.name;
    HASKOKI_FOREACH_240(M)
#undef M
    filled = (i == HASKOKI_ABI_COUNT_240);
  }
  if (!filled) {
    return 0;
  }
  k = n < HASKOKI_ABI_COUNT_240 ? n : HASKOKI_ABI_COUNT_240;
  for (i = 0; i < k; i++) {
    out[i] = cache[i];
  }
  return HASKOKI_ABI_COUNT_240;
}

int haskoki_live_interval(void) { return live_interval(); }

