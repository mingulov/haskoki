/* cbits/exports.c - versioned 3.x export surface, generated-table-backed.
 *
 * Serves the three 3.x interfaces over two physical layouts:
 *   interface 3.0 -> CK_FUNCTION_LIST_3_0 instance, version {3,0}
 *   interface 3.1 -> CK_FUNCTION_LIST_3_0 instance, version {3,1}
 *                   (separately versioned 3.0-layout table; no new struct
 *                   exists for 3.1 in any pinned header and none is defined
 *                   here - see spec/source-issues.json SRC-05)
 *   interface 3.2 -> CK_FUNCTION_LIST_3_2 instance, version {3,2}
 *
 * The 68 legacy entries of each table are the original implementations,
 * re-homed by NAME through haskoki_legacy_fns() in generated 2.40 order
 * (no cross-TU layout assumption: function_tables.c publishes designators,
 * this TU assigns designators).
 * The generated cbits/abi_stubs.inc preserves exact pinned prototypes
 * and table order. C_GetInterfaceList and C_GetInterface remain discovery
 * globals callable before initialization. C_SessionCancel and all twenty
 * message-family entries use standard_surface.c bodies in every 3.x
 * table; C_EncapsulateKey and C_DecapsulateKey retain their existing 3.2
 * routes. The remaining generated entries retain lifecycle-aware stubs.
 * Message routing changes function reachability, not mechanism advertising.
 *
 * Discovery data (interface array, tables) is static and needs no Haskell
 * entry. Tables are filled once via pthread_once on first 3.x discovery.
 */

#include <pthread.h>
#include <stddef.h>
#include <string.h>

/* Standard Cryptoki consumer pre-defines, then the pinned 3.2 superset
 * headers (declare CK_FUNCTION_LIST, CK_FUNCTION_LIST_3_0/_3_2 and all
 * CK_C_* typedefs). Resolved via -I spec/vendor. */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"
#include "abi_generated.h"
#include "abi_probe.h"
#include "async_trampoline.h"
#include "crypto_trampoline.h"

/* ---------- stub policy ---------- */

/* Routed post-2.40 definitions (exact pinned prototypes; the fill
 * macros in abi_stubs.inc wire these table slots to them). */
extern CK_RV std_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags);
extern CK_RV std_EncapsulateKey(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM_PTR pMechanism,
                                CK_OBJECT_HANDLE hPublicKey,
                                CK_ATTRIBUTE_PTR pTemplate,
                                CK_ULONG ulAttributeCount,
                                CK_BYTE_PTR pCiphertext,
                                CK_ULONG_PTR pulCiphertextLen,
                                CK_OBJECT_HANDLE_PTR phKey);
extern CK_RV std_DecapsulateKey(CK_SESSION_HANDLE hSession,
                                CK_MECHANISM_PTR pMechanism,
                                CK_OBJECT_HANDLE hPrivateKey,
                                CK_ATTRIBUTE_PTR pTemplate,
                                CK_ULONG ulAttributeCount,
                                CK_BYTE_PTR pCiphertext,
                                CK_ULONG ulCiphertextLen,
                                CK_OBJECT_HANDLE_PTR phKey);

/* Lifecycle-aware stub result: state first (matches the contract
 * order), arguments are never inspected by stubs. Fork children observe no
 * live interval via haskoki_live_interval(). */
static CK_RV x_live_check(void) {
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  return CKR_FUNCTION_NOT_SUPPORTED;
}

extern CK_RV std_MessageEncryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_EncryptMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen,
    CK_BYTE *pCiphertext, CK_ULONG *pulCiphertextLen);
extern CK_RV std_EncryptMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen);
extern CK_RV std_EncryptMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pPlaintextPart, CK_ULONG ulPlaintextPartLen,
    CK_BYTE *pCiphertextPart, CK_ULONG *pulCiphertextPartLen, CK_FLAGS flags);
extern CK_RV std_MessageEncryptFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_MessageDecryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_DecryptMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE *pCiphertext, CK_ULONG ulCiphertextLen,
    CK_BYTE *pPlaintext, CK_ULONG *pulPlaintextLen);
extern CK_RV std_DecryptMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen);
extern CK_RV std_DecryptMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pCiphertextPart, CK_ULONG ulCiphertextPartLen,
    CK_BYTE *pPlaintextPart, CK_ULONG *pulPlaintextPartLen, CK_FLAGS flags);
extern CK_RV std_MessageDecryptFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_MessageSignInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_SignMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pData, CK_ULONG ulDataLen,
    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV std_SignMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen);
extern CK_RV std_SignMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pDataPart, CK_ULONG ulDataPartLen,
    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV std_MessageSignFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_MessageVerifyInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_VerifyMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pData, CK_ULONG ulDataLen,
    CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
extern CK_RV std_VerifyMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen);
extern CK_RV std_VerifyMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pDataPart, CK_ULONG ulDataPartLen,
    CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
extern CK_RV std_MessageVerifyFinal(CK_SESSION_HANDLE hSession);

/* Generated post-2.40 stubs (exact pinned prototypes) + fill macros. */
#include "abi_stubs.inc"

/* ---------- versioned table instances ---------- */

static CK_FUNCTION_LIST_3_0 g_list_30;
static CK_FUNCTION_LIST_3_0 g_list_31; /* same layout, version {3,1} */
static CK_FUNCTION_LIST_3_2 g_list_32;

/* Interfaces in preference order: the default (underspecified) lookup
 * returns the newest interface. Names point at string literals in
 * library-owned memory, as the specification permits. */
static CK_INTERFACE g_ifaces[HASKOKI_ABI_INTERFACE_COUNT];

static pthread_once_t g_fill_once = PTHREAD_ONCE_INIT;
static int g_fill_ok = 0;

static void fill_30(CK_FUNCTION_LIST_3_0 *t, unsigned char minor,
                    haskoki_fn_t *legacy) {
  size_t i = 0;
  t->version.major = HASKOKI_ABI_300_MAJOR;
  t->version.minor = minor;
#define M(name) t->name = (CK_##name)legacy[i++];
  HASKOKI_FOREACH_240(M)
#undef M
  HASKOKI_FILL_300_NEW(t);
}

static void do_fill(void) {
  haskoki_fn_t legacy[HASKOKI_ABI_COUNT_240];
  size_t i = 0;
  size_t n;
  if (haskoki_legacy_fn_count() != HASKOKI_ABI_COUNT_240) {
    return;
  }
  n = haskoki_legacy_fns(legacy, HASKOKI_ABI_COUNT_240);
  if (n != HASKOKI_ABI_COUNT_240) {
    return;
  }
  for (i = 0; i < n; i++) {
    if (legacy[i] == 0) {
      return; /* loader contract: real functions, never NULL */
    }
  }
  fill_30(&g_list_30, HASKOKI_ABI_300_MINOR, legacy);
  fill_30(&g_list_31, HASKOKI_ABI_310_MINOR, legacy);
  g_list_32.version.major = HASKOKI_ABI_320_MAJOR;
  g_list_32.version.minor = HASKOKI_ABI_320_MINOR;
  i = 0;
#define M(name) g_list_32.name = (CK_##name)legacy[i++];
  HASKOKI_FOREACH_240(M)
#undef M
  HASKOKI_FILL_300_NEW(&g_list_32);
  HASKOKI_FILL_320_NEW(&g_list_32);

  g_ifaces[0].pInterfaceName = (CK_UTF8CHAR_PTR)HASKOKI_ABI_INTERFACE_NAME;
  g_ifaces[0].pFunctionList = &g_list_32;
  g_ifaces[0].flags = 0; /* fork-safe NOT claimed (03 section 6) */
  g_ifaces[1].pInterfaceName = (CK_UTF8CHAR_PTR)HASKOKI_ABI_INTERFACE_NAME;
  g_ifaces[1].pFunctionList = &g_list_31;
  g_ifaces[1].flags = 0;
  g_ifaces[2].pInterfaceName = (CK_UTF8CHAR_PTR)HASKOKI_ABI_INTERFACE_NAME;
  g_ifaces[2].pFunctionList = &g_list_30;
  g_ifaces[2].flags = 0;
  g_fill_ok = 1;
}

static int tables_ready(void) {
  (void)pthread_once(&g_fill_once, do_fill);
  return g_fill_ok;
}

/* ---------- exported 3.x discovery ---------- */

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList,
                         CK_ULONG_PTR pulCount) {
  if (!tables_ready()) {
    return CKR_GENERAL_ERROR;
  }
  if (pulCount == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pInterfacesList == NULL_PTR) {
    *pulCount = HASKOKI_ABI_INTERFACE_COUNT;
    return CKR_OK;
  }
  if (*pulCount < HASKOKI_ABI_INTERFACE_COUNT) {
    *pulCount = HASKOKI_ABI_INTERFACE_COUNT;
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(pInterfacesList, g_ifaces, sizeof(g_ifaces));
  *pulCount = HASKOKI_ABI_INTERFACE_COUNT;
  return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags) {
  int i;
  if (!tables_ready()) {
    return CKR_GENERAL_ERROR;
  }
  if (ppInterface == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  /* A NULL version matches any version (spec 5.4.6 rule 2); select the
   * first (newest) interface satisfying the remaining constraints. */
  for (i = 0; i < HASKOKI_ABI_INTERFACE_COUNT; i++) {
    CK_VERSION *v = (CK_VERSION *)g_ifaces[i].pFunctionList;
    if (pInterfaceName != NULL_PTR &&
        !haskoki_str_eq_bounded((const char *)pInterfaceName,
                                HASKOKI_ABI_INTERFACE_NAME, 4096)) {
      continue;
    }
    if (pVersion != NULL_PTR &&
        !haskoki_version_eq(pVersion->major, pVersion->minor, v->major,
                            v->minor)) {
      continue;
    }
    if ((flags & ~g_ifaces[i].flags) != 0) {
      continue;
    }
    *ppInterface = &g_ifaces[i];
    return CKR_OK;
  }
  return CKR_ARGUMENTS_BAD;
}

/* ---------- A1 routed-crypto trampolines ---------- */

/* RTS bootstrap (cbits/rts_bootstrap.c): Haskell entry requires it. */
extern int haskoki_rts_ensure(void);

/* Haskell crypto exports (StablePtr-based; never dereferenced here). */
extern haskoki_crypto_ctx_t haskoki_hs_crypto_open(void);
extern void haskoki_hs_crypto_close(haskoki_crypto_ctx_t ctx);
extern CK_RV haskoki_hs_crypto_digest_init(haskoki_crypto_ctx_t ctx,
                                           CK_SESSION_HANDLE hSession,
                                           CK_ULONG mech, CK_BYTE_PTR pParams,
                                           CK_ULONG ulParamsLen);
extern CK_RV haskoki_hs_crypto_digest(haskoki_crypto_ctx_t ctx,
                                      CK_SESSION_HANDLE hSession,
                                      CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                      CK_BYTE_PTR pDigest,
                                      CK_ULONG_PTR pulDigestLen);

haskoki_crypto_ctx_t haskoki_crypto_open(void) {
  if (haskoki_rts_ensure() != 0) {
    return NULL;
  }
  return haskoki_hs_crypto_open();
}

void haskoki_crypto_close(haskoki_crypto_ctx_t ctx) {
  if (haskoki_rts_ensure() != 0) {
    return;
  }
  haskoki_hs_crypto_close(ctx);
}

CK_RV haskoki_crypto_digest_init(haskoki_crypto_ctx_t ctx,
                                 CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_TYPE mech,
                                 CK_BYTE_PTR pParams, CK_ULONG ulParamsLen) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_crypto_digest_init(ctx, hSession, (CK_ULONG)mech, pParams,
                                       ulParamsLen);
}

CK_RV haskoki_crypto_digest(haskoki_crypto_ctx_t ctx, CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                            CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_crypto_digest(ctx, hSession, pData, ulDataLen, pDigest,
                                  pulDigestLen);
}

/* ---------- attached-async trampolines ---------- */

/* Haskell async exports (StablePtr-based; never dereferenced here). */
extern haskoki_async_ctx_t haskoki_hs_async_open(void);
extern void haskoki_hs_async_close(haskoki_async_ctx_t *pctx);
extern CK_RV haskoki_hs_async_digest_init(haskoki_async_ctx_t ctx,
                                          CK_SESSION_HANDLE hSession,
                                          CK_ULONG mech, CK_BYTE_PTR pParams,
                                          CK_ULONG ulParamsLen);
extern CK_RV haskoki_hs_async_start(haskoki_async_ctx_t ctx,
                                    CK_SESSION_HANDLE hSession, CK_ULONG func,
                                    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                    CK_ULONG cap, CK_ULONG ticks,
                                    haskoki_async_job_t *pHandle);
extern CK_RV haskoki_hs_async_poll(haskoki_async_ctx_t ctx,
                                   haskoki_async_job_t job, CK_ULONG func);
extern CK_RV haskoki_hs_async_complete(haskoki_async_ctx_t ctx,
                                       haskoki_async_job_t job, CK_ULONG func,
                                       CK_ASYNC_DATA_PTR pResult);
extern CK_RV haskoki_hs_async_cancel(haskoki_async_ctx_t ctx,
                                     haskoki_async_job_t job);
extern haskoki_async_store_t haskoki_hs_async_store_open(const char *path);
extern void haskoki_hs_async_store_close(haskoki_async_store_t *pbox);
extern haskoki_async_ctx_t haskoki_hs_async_open_on(haskoki_async_store_t box);
extern CK_RV haskoki_hs_async_get_id(haskoki_async_ctx_t ctx,
                                     haskoki_async_job_t job, CK_ULONG func,
                                     CK_ULONG_PTR pId);
extern CK_RV haskoki_hs_async_join(haskoki_async_ctx_t ctx, CK_ULONG id,
                                   CK_ULONG func, CK_SESSION_HANDLE hSession,
                                   CK_ULONG cap, haskoki_async_job_t *pHandle,
                                   CK_ULONG_PTR pNeed);

haskoki_async_ctx_t haskoki_async_open(void) {
  if (haskoki_rts_ensure() != 0) {
    return NULL;
  }
  return haskoki_hs_async_open();
}

void haskoki_async_close(haskoki_async_ctx_t *pctx) {
  if (haskoki_rts_ensure() != 0) {
    return;
  }
  haskoki_hs_async_close(pctx);
}

CK_RV haskoki_async_digest_init(haskoki_async_ctx_t ctx,
                               CK_SESSION_HANDLE hSession,
                               CK_MECHANISM_TYPE mech,
                               CK_BYTE_PTR pParams, CK_ULONG ulParamsLen) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_digest_init(ctx, hSession, (CK_ULONG)mech, pParams,
                                      ulParamsLen);
}

CK_RV haskoki_async_start(haskoki_async_ctx_t ctx, CK_SESSION_HANDLE hSession,
                          CK_ULONG func, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                          CK_ULONG cap, CK_ULONG ticks,
                          haskoki_async_job_t *pHandle) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_start(ctx, hSession, func, pData, ulDataLen, cap,
                                ticks, pHandle);
}

CK_RV haskoki_async_poll(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                         CK_ULONG func) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_poll(ctx, job, func);
}

CK_RV haskoki_async_complete(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                             CK_ULONG func, CK_ASYNC_DATA_PTR pResult) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_complete(ctx, job, func, pResult);
}

CK_RV haskoki_async_cancel(haskoki_async_ctx_t ctx, haskoki_async_job_t job) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_cancel(ctx, job);
}

haskoki_async_store_t haskoki_async_store_open(const char *path) {
  if (haskoki_rts_ensure() != 0) {
    return NULL;
  }
  return haskoki_hs_async_store_open(path);
}

void haskoki_async_store_close(haskoki_async_store_t *pbox) {
  if (haskoki_rts_ensure() != 0) {
    return;
  }
  haskoki_hs_async_store_close(pbox);
}

haskoki_async_ctx_t haskoki_async_open_on(haskoki_async_store_t box) {
  if (haskoki_rts_ensure() != 0) {
    return NULL;
  }
  return haskoki_hs_async_open_on(box);
}

CK_RV haskoki_async_get_id(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                           CK_ULONG func, CK_ULONG_PTR pId) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_get_id(ctx, job, func, pId);
}

CK_RV haskoki_async_join(haskoki_async_ctx_t ctx, CK_ULONG id, CK_ULONG func,
                         CK_SESSION_HANDLE hSession, CK_ULONG cap,
                         haskoki_async_job_t *pHandle, CK_ULONG_PTR pNeed) {
  if (haskoki_rts_ensure() != 0) {
    return CKR_GENERAL_ERROR;
  }
  return haskoki_hs_async_join(ctx, id, func, hSession, cap, pHandle, pNeed);
}
