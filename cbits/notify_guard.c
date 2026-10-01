#include "pkcs11.h"
#include "notify_guard.h"

static _Thread_local int in_notify;

int haskoki_in_notify(void) { return in_notify; }

/* Native callbacks must return normally across the ABI. Restore the previous
 * context (also for internal nested tests), never blindly clear an outer one.
 * Haskell calls this through a safe import on the bound application thread. */
__attribute__((visibility("hidden")))
unsigned long haskoki_invoke_notify(CK_NOTIFY notify, unsigned long session,
                                  unsigned long event, void *application) {
  int previous;
  CK_RV rv;
  if (notify == NULL_PTR) return CKR_OK;
  previous = in_notify;
  in_notify = 1;
  rv = notify(session, event, application);
  in_notify = previous;
  return rv;
}
