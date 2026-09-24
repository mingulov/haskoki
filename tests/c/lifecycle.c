/* tests/c/lifecycle.c — stale-handle lifecycle pins (DETERMINISTIC).
 *
 * Single-threaded close-then-resolve pins through the REAL entries:
 * C_WaitForSlotEvent and HASKOKI_Control must answer
 * CKR_CRYPTOKI_NOT_INITIALIZED outside an init interval (before init
 * and after finalize), in BOTH argument orders (liveness precedes
 * argument checks). A re-init after finalize must serve again (and
 * must not wedge the interval cycle).
 *
 * This probe pins the fail-fast contract; it does NOT demonstrate the
 * race (the resolve-then-enter window is narrow — the finalize/wait
 * race probe went 50/50 clean). The defect demonstration is the
 * stale-handle injection probe (tools/lifecycle-probe), driven
 * by the same script.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-lifecycle.sh.
 * Usage: lifecycle <path-to-libhaskoki.so>
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

typedef CK_RV (*HASKOKI_Control_fn)(const CK_BYTE_PTR pRequest,
                                   CK_ULONG ulRequestLen,
                                   CK_BYTE_PTR pResponse,
                                   CK_ULONG_PTR pulResponseLen);

static int g_failures = 0;

#define CHECK(cond, fmt, ...)                                                  \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("CHECK-FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
      fflush(stdout);                                                          \
      g_failures++;                                                            \
    }                                                                          \
  } while (0)

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR fns = NULL_PTR;
  HASKOKI_Control_fn pControl;
  CK_RV rv;
  CK_SLOT_ID slot = 0;
  CK_ULONG respLen = 0;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (handle == 0) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != 0, "dlsym C_GetFunctionList");
  pControl = (HASKOKI_Control_fn)dlsym(handle, "HASKOKI_Control");
  CHECK(pControl != 0, "dlsym HASKOKI_Control (extension, not in tables)");
  if (g_failures != 0) {
    return 1;
  }
  rv = pGetList(&fns);
  CHECK(rv == CKR_OK && fns != 0, "C_GetFunctionList ok");

  /* 1. Before init: both entries fail fast, whatever the arguments. */
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL_PTR);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "wait-before-init -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL_PTR, NULL_PTR);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "wait-before-init null-slot -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);
  respLen = 0;
  rv = pControl(NULL_PTR, 0, NULL_PTR, &respLen);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "control-before-init -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);
  rv = pControl(NULL_PTR, 0, NULL_PTR, NULL_PTR);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "control-before-init null-len -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);

  /* 2. Live interval: entries serve (empty queue -> NO_EVENT). */
  rv = fns->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok (rv=0x%lx)", (unsigned long)rv);
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL_PTR);
  CHECK(rv == CKR_NO_EVENT, "wait-live empty -> NO_EVENT (rv=0x%lx)", (unsigned long)rv);
  /* Live + bad arguments: argument checks fire (liveness passes). */
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL_PTR, NULL_PTR);
  CHECK(rv == CKR_ARGUMENTS_BAD, "wait-live null-slot -> ARGUMENTS_BAD (rv=0x%lx)",
        (unsigned long)rv);
  rv = pControl(NULL_PTR, 0, NULL_PTR, NULL_PTR);
  CHECK(rv == CKR_ARGUMENTS_BAD, "control-live null-len -> ARGUMENTS_BAD (rv=0x%lx)",
        (unsigned long)rv);

  /* 3. After finalize: close-then-resolve fails fast on both paths. */
  rv = fns->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok (rv=0x%lx)", (unsigned long)rv);
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL_PTR);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "wait-after-finalize -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL_PTR, NULL_PTR);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "wait-after-finalize null-slot -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);
  respLen = 0;
  rv = pControl(NULL_PTR, 0, NULL_PTR, &respLen);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "control-after-finalize -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);
  rv = pControl(NULL_PTR, 0, NULL_PTR, NULL_PTR);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED, "control-after-finalize null-len -> NOT_INITIALIZED (rv=0x%lx)",
        (unsigned long)rv);

  /* 4. Re-init serves again (no wedged interval cycle). */
  rv = fns->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize-again ok (rv=0x%lx)", (unsigned long)rv);
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL_PTR);
  CHECK(rv == CKR_NO_EVENT, "wait-reinit empty -> NO_EVENT (rv=0x%lx)", (unsigned long)rv);
  rv = fns->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize-again ok (rv=0x%lx)", (unsigned long)rv);

  if (g_failures != 0) {
    printf("LIFECYCLE-PINS: %d FAILURES\n", g_failures);
    return 1;
  }
  printf("LIFECYCLE-PINS: all 19 checks passed\n");
  return 0;
}
