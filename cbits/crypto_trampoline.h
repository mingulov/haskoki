/* cbits/crypto_trampoline.h - A1 routed-crypto trampoline API.
 *
 * Thin CK-typed forwards to the Haskell crypto exports
 * (haskoki_hs_crypto_* in ffi/Haskoki/FFI/Exports.hs): the digest
 * proof path across the real export boundary. Full table-slot
 * routing is later work; these entry points prove the linkage.
 *
 * A context owns an Env, a live OpenSSL4 backend, and exactly one
 * proof session. Every call names that session; anything else fails
 * with CKR_SESSION_HANDLE_INVALID.
 */
#ifndef HASKOKI_CRYPTO_TRAMPOLINE_H
#define HASKOKI_CRYPTO_TRAMPOLINE_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

/* Opaque caller-owned context (a Haskell StablePtr, never dereferenced). */
typedef void *haskoki_crypto_ctx_t;

haskoki_crypto_ctx_t haskoki_crypto_open(void);
void haskoki_crypto_close(haskoki_crypto_ctx_t ctx);
CK_RV haskoki_crypto_digest_init(haskoki_crypto_ctx_t ctx,
                                 CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_TYPE mech,
                                 CK_BYTE_PTR pParams, CK_ULONG ulParamsLen);
CK_RV haskoki_crypto_digest(haskoki_crypto_ctx_t ctx, CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                            CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

#endif /* HASKOKI_CRYPTO_TRAMPOLINE_H */
