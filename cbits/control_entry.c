/* cbits/control_entry.c — control instance root + HASKOKI_Control.
 *
 * Owns the per-init-interval control instance handle (a StablePtr from
 * Haskoki.FFI.Instance): installed by C_Initialize, uninstalled by
 * C_Finalize. HASKOKI_Control and the C_WaitForSlotEvent body both
 * resolve the SAME handle through haskoki_instance_get(), so a native
 * waiter and a control call in one process always share one
 * instance. Haskell manages the handle lifetime (open/close
 * exports). Close discards shared pending flags and unbinds the control
 * owner before Standard teardown, making undecided waiters runnable.
 *
 * Discipline: Control borrows the Standard owner under the C state lock
 * and revalidates liveness after acquiring it. The blocking wait path
 * alone remains free of that lock.
 *
 * The handle is an atomic pointer (the standard-surface
 * precedent): install release-stores under the init lock, serving
 * bodies acquire-load lock-free, shutdown exchange-NULLs under the
 * init lock. The atomicity kills the data race (no load hoisting
 * across serving calls, cross-thread install visibility) — but the
 * lifecycle race (resolve-then-enter across close,
 * deRef-after-free) closes one layer up, where the free happens:
 * the Haskell per-handle liveness cell (Instance.hs) is never freed, so
 * every deRef is memory-safe by construction, and a taken (closed)
 * cell answers CKR_CRYPTOKI_NOT_INITIALIZED. A C-side generation
 * counter cannot provide that lease (C cannot observe Haskell entry
 * completion, so no C-side grace period is sound under
 * preemption).
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "haskoki_control.h"
#include "notify_guard.h"

/* Haskell instance exports (ffi/Haskoki/FFI/Instance.hs). Prefer the
 * GHC-generated stub header when available; else the manual
 * declarations below (HsPtr/HsWord64/HsWord8 shapes). */
#if defined(__has_include)
#if __has_include("Haskoki/FFI/Instance_stub.h")
#include "Haskoki/FFI/Instance_stub.h"
#define HASKOKI_HAVE_INSTANCE_STUB_H 1
#elif __has_include("Haskoki_FFI_Instance_stub.h")
#include "Haskoki_FFI_Instance_stub.h"
#define HASKOKI_HAVE_INSTANCE_STUB_H 1
#endif
#endif
#ifndef HASKOKI_HAVE_INSTANCE_STUB_H
#include <stdint.h>
extern void *haskoki_instance_open(void);
extern void haskoki_instance_close(void *instance);
extern unsigned long haskoki_wait_for_slot_event(void *instance, unsigned long flags,
                                                 unsigned long *p_slot);
extern uint64_t haskoki_control(void *instance, const uint8_t *p_request,
                                uint64_t request_len, uint8_t *p_response,
                                uint64_t *p_response_len);
#endif

/* Local cryptoki values (pinned v2.40; this TU serves the table body
 * too, so it cannot assume the caller's headers). */
#define CKR_OK_INSTANCE 0x00000000UL
#define CKR_FUNCTION_FAILED_INSTANCE 0x00000006UL
#define CKR_GENERAL_ERROR_INSTANCE 0x00000005UL
#define CKR_ARGUMENTS_BAD_INSTANCE 0x00000007UL
#define CKR_CRYPTOKI_NOT_INITIALIZED_INSTANCE 0x00000190UL

/* The live instance handle, or NULL outside an init interval.
 * Atomic: install release-stores under the init lock while serving
 * bodies acquire-load lock-free, so no serving call can hoist a
 * stale load and every install is visible cross-thread. */
static _Atomic(void *) g_haskoki_instance = ATOMIC_VAR_INIT(0);

/* Install (C_Initialize) / uninstall (C_Finalize) the handle. */
void haskoki_instance_install(void *instance) {
  atomic_store_explicit(&g_haskoki_instance, instance, memory_order_release);
}

void *haskoki_instance_get(void) {
  return atomic_load_explicit(&g_haskoki_instance, memory_order_acquire);
}

/* Open a fresh owned instance (C_Initialize path). */
void *haskoki_instance_open_fresh(void) { return haskoki_instance_open(); }

/* Under init + state locks, unpublish first, then close/unbind through Haskell
 * before Standard teardown. The emptied InstanceCell/StablePtr is retained
 * forever (one per interval); it is not freed here or by Haskell. A waiter
 * which captured it before this exchange may enter safely after reopen and
 * still observes the old closed interval. Idempotent on NULL. The historical
 * plain-pointer publication race is distinct from that retained-cell lease. */
void haskoki_instance_shutdown(void) {
  void *inst =
      atomic_exchange_explicit(&g_haskoki_instance, 0, memory_order_acq_rel);
  if (inst != 0) {
    haskoki_instance_close(inst);
  }
}

/* Blocking/nonblocking slot-event wait body for the legacy table
 * slot (and, through it, the 3.x tables). Never takes the C state
 * lock: blocking calls must not serialize the module. The single
 * acquire-load snapshot either enters Haskell with a published
 * handle (the Haskell liveness cell re-validates before serving)
 * or fails fast. Never reload the root after capturing this interval. */
unsigned long haskoki_instance_wait_for_slot_event(unsigned long flags, unsigned long *p_slot) {
  if (haskoki_in_notify()) return CKR_FUNCTION_FAILED_INSTANCE;
  void *inst = atomic_load_explicit(&g_haskoki_instance, memory_order_acquire);
  if (inst == 0) {
    return (uint64_t)CKR_CRYPTOKI_NOT_INITIALIZED_INSTANCE;
  }
  if (p_slot == 0) {
    return (uint64_t)CKR_ARGUMENTS_BAD_INSTANCE;
  }
  return haskoki_wait_for_slot_event(inst, flags, p_slot);
}

extern int haskoki_live_interval(void);
extern unsigned long haskoki_state_lock(void);
extern unsigned long haskoki_state_unlock(void);

/* The extension entry point: a global symbol, in no function table. */
HASKOKI_RV HASKOKI_Control(const HASKOKI_BYTE *pRequest,
                           HASKOKI_ULONG ulRequestLen,
                           HASKOKI_BYTE *pResponse,
                           HASKOKI_ULONG *pulResponseLen) {
  if (haskoki_in_notify()) return CKR_FUNCTION_FAILED_INSTANCE;
  void *inst;
  unsigned long rv;
  if (!haskoki_live_interval()) {
    return (HASKOKI_RV)CKR_CRYPTOKI_NOT_INITIALIZED_INSTANCE;
  }
  inst = atomic_load_explicit(&g_haskoki_instance, memory_order_acquire);
  if (inst == 0) {
    return (HASKOKI_RV)CKR_CRYPTOKI_NOT_INITIALIZED_INSTANCE;
  }
  rv = haskoki_state_lock();
  if (rv != CKR_OK_INSTANCE) {
    return (HASKOKI_RV)rv;
  }
  /* Authoritative after-lock validation, including budget/status queries.
   * A caller from an old interval must not borrow a new interval's owner. */
  if (!haskoki_live_interval() ||
      inst != atomic_load_explicit(&g_haskoki_instance, memory_order_acquire)) {
    rv = CKR_CRYPTOKI_NOT_INITIALIZED_INSTANCE;
  } else if (pulResponseLen == 0) {
    rv = CKR_ARGUMENTS_BAD_INSTANCE;
  } else if (pRequest == 0 && ulRequestLen != 0) {
    rv = CKR_ARGUMENTS_BAD_INSTANCE;
  } else if (ulRequestLen > 0xFFFFFFFFUL) {
    rv = CKR_GENERAL_ERROR_INSTANCE;
  } else {
    /* The export copies the request bytes and never writes through them. */
    rv = haskoki_control(inst, (uint8_t *)pRequest, (uint64_t)ulRequestLen,
                         (uint8_t *)pResponse, (uint64_t *)pulResponseLen);
  }
  (void)haskoki_state_unlock();
  return (HASKOKI_RV)rv;
}
