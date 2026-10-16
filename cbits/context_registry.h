#ifndef HASKOKI_CONTEXT_REGISTRY_H
#define HASKOKI_CONTEXT_REGISTRY_H

/* Process-wide async-context registry behind Haskoki.FFI.Async.
 *
 * C-owned surface state (the table-mint precedent: one mutex, one
 * locked step per call): maps context-pointer bits to the admission
 * entry. The Haskell side holds no process-wide cell and reaches
 * this table only through the narrow calls below.
 *
 * Kind codes: 1 names a live owned context, 2 a live borrowed view
 * (admit-only, never teardown authority). A lookup reports 0 for an
 * absent key (never registered: a foreign value, or a hook-only
 * park), which refuses like a tombstone, 1 or 2 for a live entry
 * with its table root, and 3 for a tombstone (refuses without
 * dereferencing; carries no table). A tombstone persists until its
 * pointer value is reused: the next owner re-registers over it.
 * Retiring also clears the entry hook in the same locked step, so a
 * reused pointer value never fires a stale hook.
 *
 * Table and hook references cross as Haskell StablePtr values with
 * borrower-safe reclamation. A lookup that hands one out holds a
 * borrow on its entry; the caller dereferences and then releases
 * (dereference strictly before release, both adjacent to the
 * lookup, under a mask). Every displaced root — from retire,
 * replacement registration, or hook replacement — queues on its
 * entry, however many displacements stack while borrows stand; no
 * overwrite ever strands an older root. The caller drains taken
 * roots through 'haskoki_ctx_take_reclaimable' (which hands out
 * only roots whose entry holds no borrow) and frees each one,
 * reporting the batch through 'haskoki_ctx_note_freed'. A root is
 * therefore freed only when no holder can still dereference it,
 * every root is preserved until freed, and nothing stands retained
 * past joined teardown. 'haskoki_ctx_pending' reports the live
 * backlog (queued roots), which drains to zero at quiescence;
 * 'haskoki_ctx_stats' reports the independent
 * displaced/taken/freed accounting, which balances at quiescence.
 *
 * Allocation failure aborts: silently dropping a register, a retire,
 * or a queued root would corrupt admission or strand a root, so the
 * table stops the process instead of misbehaving.
 */

__attribute__((visibility("hidden"))) void haskoki_ctx_register(void *key,
                                                                int kind,
                                                                void *table);
__attribute__((visibility("hidden"))) void haskoki_ctx_retire(void *key);
__attribute__((visibility("hidden"))) int haskoki_ctx_lookup_acquire(void *key,
                                                                     void **table_out);
__attribute__((visibility("hidden"))) void haskoki_ctx_hook_set(void *key,
                                                                void *hook);
__attribute__((visibility("hidden"))) int haskoki_ctx_hook_acquire(void *key,
                                                                   void **hook_out);
__attribute__((visibility("hidden"))) void haskoki_ctx_release(void *key);
__attribute__((visibility("hidden"))) int haskoki_ctx_take_reclaimable(void **root_out);
__attribute__((visibility("hidden"))) void haskoki_ctx_note_freed(int n);
__attribute__((visibility("hidden"))) int haskoki_ctx_pending(void);
__attribute__((visibility("hidden"))) void haskoki_ctx_stats(unsigned long long *displaced_out,
                                                             unsigned long long *taken_out,
                                                             unsigned long long *freed_out);

/* Process residue cell, a separate C-owned cell under its own mutex.
 *
 * Holds the Stores a failed standalone open could not close (two
 * cleanup closes failed) and could not hand to a caller: the C
 * exports, and an asynchronous primary. Each entry is a Haskell
 * StablePtr root to the Store. The cell grows with realloc and never
 * drops an entry.
 *
 * Fail closed: an open that may queue a Store first reserves a slot
 * ('haskoki_residue_reserve', before it acquires the Store). A
 * reservation that cannot allocate reports 0 and the open refuses,
 * holding nothing. A push consumes the caller's reservation, so it
 * always fits; an open that queued nothing returns its reservation
 * ('haskoki_residue_release').
 *
 * Every later standalone open and close takes the queued entries
 * (newest first: take pops the tail; each take moves one entry in
 * flight and keeps its slot), tries one close per entry, frees the
 * root of each Store it closed and reports the batch through
 * 'haskoki_residue_note_closed', and puts the rest back. A put-back
 * always fits: the entry kept its slot while in flight.
 * 'haskoki_residue_count' reports queued plus in-flight entries, so
 * the count never dips while another thread holds an entry mid-retry.
 *
 * Protocol slips are never silent. A push without a reservation, a
 * release without one, a put-back with nothing in flight, and a
 * note_closed beyond the in-flight count each bump
 * 'haskoki_residue_anomalies' (test-visible; zero in a correct run).
 * A push without a reservation still queues when the cell can grow
 * and reports 0 otherwise (the caller keeps the root). A put-back with
 * nothing in flight still queues the root, growing the cell, and
 * aborts when the cell cannot grow: it never drops a root.
 */
__attribute__((visibility("hidden"))) int haskoki_residue_reserve(void);
__attribute__((visibility("hidden"))) void haskoki_residue_release(void);
__attribute__((visibility("hidden"))) int haskoki_residue_push(void *root);
__attribute__((visibility("hidden"))) int haskoki_residue_take(void **root_out);
__attribute__((visibility("hidden"))) void haskoki_residue_put_back(void *root);
__attribute__((visibility("hidden"))) void haskoki_residue_note_closed(int n);
__attribute__((visibility("hidden"))) int haskoki_residue_count(void);
__attribute__((visibility("hidden"))) unsigned long long haskoki_residue_anomalies(void);

#endif
