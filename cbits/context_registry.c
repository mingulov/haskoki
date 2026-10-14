/* cbits/context_registry.c — C-owned async-context registry.
 *
 * Owns the process-wide map from context-pointer bits to the
 * admission entry behind Haskoki.FFI.Async: live owned entries,
 * live borrowed entries (admit-only), tombstones, and the per-entry
 * test hooks. One mutex serializes every call; each call completes
 * in one locked step with no callbacks into Haskell and no blocking
 * past the brief lock, so the Haskell side reaches it through
 * unsafe imports.
 *
 * Entries are a small dynamic array under linear scan: the live set
 * is tiny (one entry per open context plus one tombstone per close
 * until its pointer value is reused), so a hash table would only
 * obscure the audit. Register preserves an existing hook (hooks
 * clear only through an explicit clear or through retire, in the
 * same locked step as the tombstone). A hook set on a
 * never-registered key parks in a hook-only slot that reads as
 * absent for admission while still firing the hook — the exact
 * prior two-map behavior.
 *
 * Roots are Haskell StablePtr values with borrower-safe
 * reclamation (see the header note): lookups that hand a root out
 * count a borrow, the caller dereferences then releases, every
 * displaced root queues on its entry no matter how many stack up,
 * and the caller drains and frees taken roots. Taken roots come
 * only from entries holding no borrow, so a freed root can never
 * still be dereferenced.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>

#include "context_registry.h"

/* Entry states, mirrored by the Haskell accessors. */
enum {
  CTX_HOOK_ONLY = 0, /* hook parked, no context entry: reads as absent */
  CTX_OWNED = 1,     /* live owned context */
  CTX_BORROWED = 2,  /* live borrowed view (admit-only) */
  CTX_RETIRED = 3    /* tombstone: refuses, carries no table */
};

struct ctx_entry {
  void *key;
  int state;
  void *table;       /* live table root, or NULL */
  void *hook;        /* armed hook root, or NULL */
  unsigned refs;     /* outstanding borrowed-root holders */
  void **dead;       /* queued displaced roots, oldest first */
  size_t dead_len;
  size_t dead_cap;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ctx_entry *g_entries = NULL;
static size_t g_len = 0;
static size_t g_cap = 0;
static unsigned long long g_displaced = 0;
static unsigned long long g_taken = 0;
static unsigned long long g_freed = 0;

/* Caller holds g_mu. */
static struct ctx_entry *find_entry(void *key) {
  size_t i;
  for (i = 0; i < g_len; i++) {
    if (g_entries[i].key == key)
      return &g_entries[i];
  }
  return NULL;
}

/* Caller holds g_mu. Aborts when the table cannot grow (see the
 * header note): admission must never silently degrade. */
static struct ctx_entry *find_or_append(void *key) {
  struct ctx_entry *found = find_entry(key);
  struct ctx_entry *grown;
  size_t want;
  if (found != NULL)
    return found;
  if (g_len == g_cap) {
    want = (g_cap == 0) ? 64 : (g_cap * 2);
    grown = (struct ctx_entry *)realloc(g_entries,
                                        want * sizeof(*g_entries));
    if (grown == NULL)
      abort();
    g_entries = grown;
    g_cap = want;
  }
  g_entries[g_len].key = key;
  g_entries[g_len].state = CTX_HOOK_ONLY;
  g_entries[g_len].table = NULL;
  g_entries[g_len].hook = NULL;
  g_entries[g_len].refs = 0;
  g_entries[g_len].dead = NULL;
  g_entries[g_len].dead_len = 0;
  g_entries[g_len].dead_cap = 0;
  g_len++;
  return &g_entries[g_len - 1];
}

/* Caller holds g_mu. Queues one displaced root on its entry;
 * every displacement is preserved, however many stack while
 * borrows stand. Aborts when the queue cannot grow. */
static void queue_dead(struct ctx_entry *e, void *old) {
  void **grown;
  size_t want;
  if (old == NULL)
    return;
  if (e->dead_len == e->dead_cap) {
    want = (e->dead_cap == 0) ? 4 : (e->dead_cap * 2);
    grown = (void **)realloc(e->dead, want * sizeof(*e->dead));
    if (grown == NULL)
      abort();
    e->dead = grown;
    e->dead_cap = want;
  }
  e->dead[e->dead_len] = old;
  e->dead_len++;
  g_displaced++;
}

__attribute__((visibility("hidden"))) void
haskoki_ctx_register(void *key, int kind, void *table) {
  struct ctx_entry *e;
  void *old;
  if (key == NULL || table == NULL)
    return;
  if (kind != CTX_OWNED && kind != CTX_BORROWED)
    return;
  pthread_mutex_lock(&g_mu);
  e = find_or_append(key);
  old = e->table;
  e->state = kind;
  e->table = table;
  /* The hook (if any) stands: registration never arms or clears. */
  queue_dead(e, old);
  pthread_mutex_unlock(&g_mu);
}

__attribute__((visibility("hidden"))) void
haskoki_ctx_retire(void *key) {
  struct ctx_entry *e;
  void *old_table;
  void *old_hook;
  if (key == NULL)
    return;
  pthread_mutex_lock(&g_mu);
  e = find_or_append(key);
  old_table = e->table;
  old_hook = e->hook;
  e->state = CTX_RETIRED;
  e->table = NULL;
  e->hook = NULL;
  queue_dead(e, old_table);
  queue_dead(e, old_hook);
  pthread_mutex_unlock(&g_mu);
}

__attribute__((visibility("hidden"))) int
haskoki_ctx_lookup_acquire(void *key, void **table_out) {
  struct ctx_entry *e;
  int state;
  void *table;
  if (key == NULL) {
    if (table_out != NULL)
      *table_out = NULL;
    return CTX_HOOK_ONLY;
  }
  pthread_mutex_lock(&g_mu);
  e = find_entry(key);
  if (e == NULL || e->state == CTX_HOOK_ONLY) {
    state = CTX_HOOK_ONLY;
    table = NULL;
  } else if (e->state == CTX_RETIRED) {
    state = CTX_RETIRED;
    table = NULL;
  } else {
    state = e->state;
    table = e->table;
    e->refs++;
  }
  pthread_mutex_unlock(&g_mu);
  if (table_out != NULL)
    *table_out = table;
  return state;
}

__attribute__((visibility("hidden"))) void
haskoki_ctx_hook_set(void *key, void *hook) {
  struct ctx_entry *e;
  void *old;
  if (key == NULL)
    return;
  pthread_mutex_lock(&g_mu);
  if (hook == NULL) {
    e = find_entry(key);
    if (e != NULL) {
      old = e->hook;
      e->hook = NULL;
      queue_dead(e, old);
    }
  } else {
    e = find_or_append(key);
    old = e->hook;
    e->hook = hook;
    queue_dead(e, old);
  }
  pthread_mutex_unlock(&g_mu);
}

__attribute__((visibility("hidden"))) int
haskoki_ctx_hook_acquire(void *key, void **hook_out) {
  struct ctx_entry *e;
  void *hook = NULL;
  if (key == NULL) {
    if (hook_out != NULL)
      *hook_out = NULL;
    return 0;
  }
  pthread_mutex_lock(&g_mu);
  e = find_entry(key);
  if (e != NULL && e->hook != NULL) {
    hook = e->hook;
    e->refs++;
  }
  pthread_mutex_unlock(&g_mu);
  if (hook_out != NULL)
    *hook_out = hook;
  return hook != NULL ? 1 : 0;
}

__attribute__((visibility("hidden"))) void
haskoki_ctx_release(void *key) {
  struct ctx_entry *e;
  if (key == NULL)
    return;
  pthread_mutex_lock(&g_mu);
  e = find_entry(key);
  if (e != NULL && e->refs > 0)
    e->refs--;
  pthread_mutex_unlock(&g_mu);
}

__attribute__((visibility("hidden"))) int
haskoki_ctx_take_reclaimable(void **root_out) {
  size_t i;
  if (root_out != NULL)
    *root_out = NULL;
  pthread_mutex_lock(&g_mu);
  for (i = 0; i < g_len; i++) {
    struct ctx_entry *e = &g_entries[i];
    if (e->refs == 0 && e->dead_len > 0) {
      e->dead_len--;
      if (root_out != NULL)
        *root_out = e->dead[e->dead_len];
      g_taken++;
      pthread_mutex_unlock(&g_mu);
      return 1;
    }
  }
  pthread_mutex_unlock(&g_mu);
  return 0;
}

__attribute__((visibility("hidden"))) void
haskoki_ctx_note_freed(int n) {
  if (n <= 0)
    return;
  pthread_mutex_lock(&g_mu);
  g_freed += (unsigned long long)n;
  pthread_mutex_unlock(&g_mu);
}

__attribute__((visibility("hidden"))) int
haskoki_ctx_pending(void) {
  size_t i;
  size_t pending = 0;
  pthread_mutex_lock(&g_mu);
  for (i = 0; i < g_len; i++)
    pending += g_entries[i].dead_len;
  pthread_mutex_unlock(&g_mu);
  return (int)pending;
}

__attribute__((visibility("hidden"))) void
haskoki_ctx_stats(unsigned long long *displaced_out,
                  unsigned long long *taken_out,
                  unsigned long long *freed_out) {
  pthread_mutex_lock(&g_mu);
  if (displaced_out != NULL)
    *displaced_out = g_displaced;
  if (taken_out != NULL)
    *taken_out = g_taken;
  if (freed_out != NULL)
    *freed_out = g_freed;
  pthread_mutex_unlock(&g_mu);
}
