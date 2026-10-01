/* Test executable only. Every callback returns normally across the C ABI. */
#include <pthread.h>
#include "pkcs11.h"
extern int haskoki_in_notify(void);
extern unsigned long haskoki_invoke_notify(CK_NOTIFY, unsigned long, unsigned long, void *);

static _Thread_local pthread_t caller;
static _Thread_local unsigned long calls, session_seen, event_seen, result;
static _Thread_local unsigned long same_thread, guarded, restored, fenced;
static _Thread_local void *cookie_seen;

void notifications_reset(unsigned long rv) {
  caller = pthread_self();
  calls = session_seen = event_seen = same_thread = guarded = restored = fenced = 0;
  cookie_seen = NULL;
  result = rv;
}
/* Simulated language failure is caught inside this adapter, before return to
 * the invoker. This is a status protocol, never a foreign exception/longjmp. */
static int language_action(unsigned long *rv) {
  if (result == 0xdeadUL) return 0;
  *rv = result;
  return 1;
}
CK_RV notifications_callback(CK_SESSION_HANDLE session, CK_NOTIFICATION event, void *cookie) {
  CK_RV rv = CKR_FUNCTION_FAILED;
  ++calls;
  session_seen = session;
  event_seen = event;
  cookie_seen = cookie;
  same_thread = pthread_equal(caller, pthread_self()) != 0;
  guarded = haskoki_in_notify() != 0;
  if (!language_action(&rv)) ++fenced;
  return rv;
}
unsigned long notifications_invoke(CK_NOTIFY notify, unsigned long session,
                                   unsigned long event, void *cookie) {
  int previous = haskoki_in_notify();
  unsigned long rv = haskoki_invoke_notify(notify, session, event, cookie);
  restored = haskoki_in_notify() == previous;
  return rv;
}
unsigned long notifications_read(unsigned long field) {
  switch (field) {
  case 0: return calls;
  case 1: return session_seen;
  case 2: return event_seen;
  case 3: return same_thread;
  case 4: return guarded;
  case 5: return restored;
  case 6: return fenced;
  default: return ~0UL;
  }
}
void *notifications_cookie(void) { return cookie_seen; }
