#ifndef HASKOKI_NOTIFY_GUARD_H
#define HASKOKI_NOTIFY_GUARD_H
/* Type independent: safe in the legacy mirror TU as well as vendor-header TUs.
 * The invoker's CK_NOTIFY signature is defined against the pinned header in
 * notify_guard.c. Explicit visibility keeps both helpers out of the dynamic API. */
__attribute__((visibility("hidden"))) int haskoki_in_notify(void);
#endif
