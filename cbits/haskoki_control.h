/* cbits/haskoki_control.h — HASKOKI_Control extension entry.
 *
 * In-process control for the OWNED module handle: a harness that
 * already loaded libhaskoki.so calls this symbol on that same handle
 * to affect the same in-process provider state. This is NOT a PKCS#11
 * standard entry point: it lives in no function table (2.40 or 3.x)
 * and is resolved separately with the native loader (dlsym).
 *
 * The request is bounded UTF-8 JSON (see Haskoki.Runtime.Control for
 * the envelope); the response is UTF-8 JSON without a trailing NUL.
 * Response budget rule (§5.1):
 *
 *   - pResponse == NULL is a pure budget query: returns CKR_OK and
 *     stores 65536 through pulResponseLen; executes nothing.
 *   - *pulResponseLen below HASKOKI_CONTROL_BUDGET returns
 *     CKR_BUFFER_TOO_SMALL, stores 65536, and executes nothing.
 *   - otherwise the command executes once and the actual response
 *     length is stored through pulResponseLen.
 *
 * pulResponseLen == NULL is CKR_ARGUMENTS_BAD. Unknown commands and
 * malformed requests return CKR_ARGUMENTS_BAD without mutation.
 * Requires an initialized instance with control enabled.
 */
#ifndef HASKOKI_CONTROL_H
#define HASKOKI_CONTROL_H

/* Fixed §5.1 response budget in bytes. */
#define HASKOKI_CONTROL_BUDGET 65536UL

/* Fixed §5.1 schema version carried by every envelope. */
#define HASKOKI_CONTROL_SCHEMA_VERSION 1

#ifndef HASKOKI_CONTROL_NO_PROTOTYPE

/* Minimal cryptoki-shaped types so consumers need no PKCS#11 header.
 * Layout-compatible with the pinned headers (unsigned long RV/len). */
typedef unsigned long HASKOKI_RV;
typedef unsigned long HASKOKI_ULONG;
typedef unsigned char HASKOKI_BYTE;

#ifdef __cplusplus
extern "C" {
#endif

HASKOKI_RV HASKOKI_Control(const HASKOKI_BYTE *pRequest,
                           HASKOKI_ULONG ulRequestLen,
                           HASKOKI_BYTE *pResponse,
                           HASKOKI_ULONG *pulResponseLen);

#ifdef __cplusplus
}
#endif

#endif /* HASKOKI_CONTROL_NO_PROTOTYPE */

#endif /* HASKOKI_CONTROL_H */
