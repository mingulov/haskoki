/* Process-wide async-table identity mint behind Haskoki.Runtime.Async.
 *
 * C-owned surface state (one atomic cell, one atomic step per mint):
 * hands out table indices 0, 1, ... Past 2^32-1 tables it refuses
 * (-1) instead of wrapping or reusing an identity, leaving the
 * counter untouched, so a refused mint consumes nothing and salts
 * never repeat. The Haskell side maps an index to its exact salt. */
#include <stdatomic.h>
#include <stdint.h>

static _Atomic(int64_t) g_table_next = 0;

__attribute__((visibility("hidden")))
int64_t haskoki_table_mint_next(void) {
  int64_t seen = atomic_load(&g_table_next);
  for (;;) {
    if (seen >= INT64_C(0xFFFFFFFF))
      return -1;
    if (atomic_compare_exchange_weak(&g_table_next, &seen, seen + 1))
      return seen;
  }
}
