/* cbits/async_trampoline.h - attached-async trampoline API.
 *
 * Thin CK-typed forwards to the Haskell async exports
 * (haskoki_hs_async_* in ffi/Haskoki/FFI/Async.hs): the private proof
 * path across the real export boundary. These exports retain context
 * and opaque job-token identity, completion version 1, successful Join
 * CKR_PENDING plus a private handle, and the query/short-buffer proof
 * dialogue (including Join's optional need out-pointer).
 *
 * A context owns an Env, a live OpenSSL4 backend, exactly one proof
 * session, and one attached-job table. Close runs through the
 * handle slot and nulls it (idempotent). Jobs are opaque native
 * tokens freed exactly once on their terminal path.
 *
 * The public 3.2 table adapter instead resolves a standard session and
 * function name, borrows the standard environment/backend and shared
 * job table, and keeps private handles internally. Complete performs
 * one poll then completes when ready, publishes version 0, and uses
 * output storage bound at submission or Join; incoming result fields
 * do not replace that allocation. Successful public Join returns CKR_OK
 * after binding installation; capacity is by value, with no need output
 * or public query. The private proof API above remains unchanged.
 */
#ifndef HASKOKI_ASYNC_TRAMPOLINE_H
#define HASKOKI_ASYNC_TRAMPOLINE_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

/* Opaque caller-owned context (a Haskell StablePtr, never dereferenced). */
typedef void *haskoki_async_ctx_t;

/* Opaque native job token (a Haskell StablePtr, never dereferenced). */
typedef void *haskoki_async_job_t;

/* Opaque process-level store (a Haskell StablePtr, never
 * dereferenced). Outlives every context opened on it. */
typedef void *haskoki_async_store_t;

haskoki_async_ctx_t haskoki_async_open(void);
void haskoki_async_close(haskoki_async_ctx_t *pctx);
haskoki_async_store_t haskoki_async_store_open(const char *path);
void haskoki_async_store_close(haskoki_async_store_t *pbox);
haskoki_async_ctx_t haskoki_async_open_on(haskoki_async_store_t box);
CK_RV haskoki_async_digest_init(haskoki_async_ctx_t ctx,
                               CK_SESSION_HANDLE hSession,
                               CK_MECHANISM_TYPE mech,
                               CK_BYTE_PTR pParams, CK_ULONG ulParamsLen);
CK_RV haskoki_async_start(haskoki_async_ctx_t ctx, CK_SESSION_HANDLE hSession,
                          CK_ULONG func, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                          CK_ULONG cap, CK_ULONG ticks,
                          haskoki_async_job_t *pHandle);
CK_RV haskoki_async_poll(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                         CK_ULONG func);
CK_RV haskoki_async_complete(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                             CK_ULONG func, CK_ASYNC_DATA_PTR pResult);
CK_RV haskoki_async_cancel(haskoki_async_ctx_t ctx, haskoki_async_job_t job);
CK_RV haskoki_async_get_id(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                           CK_ULONG func, CK_ULONG_PTR pId);
CK_RV haskoki_async_join(haskoki_async_ctx_t ctx, CK_ULONG id, CK_ULONG func,
                         CK_SESSION_HANDLE hSession, CK_ULONG cap,
                         haskoki_async_job_t *pHandle, CK_ULONG_PTR pNeed);

#endif /* HASKOKI_ASYNC_TRAMPOLINE_H */
