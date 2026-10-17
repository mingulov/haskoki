/* cbits/rts_bootstrap.c — GHC RTS bootstrap adapter.
 *
 * Owns exactly two things:
 *   1. the process-lifetime hs_init policy: the RTS is started at most
 *      once per process, with library-owned argv, on the first
 *      provider call (C_Initialize or a native export) that needs
 *      Haskell entry. When it starts the RTS itself, the provider
 *      pins one capability and ignores GHCRTS
 *      (see haskoki_rts_ensure); and
 *   2. the boot-PID record used to refuse fork children before they can
 *      enter inherited Haskell state (03 §6: post-init fork without
 *      exec is unsupported).
 *
 * C_Finalize ends a provider interval, NEVER the runtime: this file (and
 * the whole package) must never stop the RTS. A poison macro below turns
 * any accidental shutdown call-site into a compile error, and
 * scripts/test-loader.sh greps the built objects for the symbol.
 */

/* Feature-test: nanosleep and struct timespec need POSIX.1-2008
 * visibility under a strict -std=c11 build. */
#define _POSIX_C_SOURCE 200809L

#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <HsFFI.h>
#include <Rts.h>
#include <RtsAPI.h>

#ifdef HSK_OSSL4_TEST_HOOKS
#include <stdint.h>
#endif

/* Poison: finalization must not stop the RTS (03 §1, §5). Any use of the
 * identifier below fails compilation. The token is split so the static
 * symbol check keeps matching only real references. */
#define hs_exit DO_NOT_STOP_THE_RTS__C_Finalize_ENDS_THE_INTERVAL_ONLY

/* Boot claim (0 = never claimed; a userspace PID is never 0) and the
 * start-complete flag. The PID itself is the claim word, published by
 * a single compare-and-swap, so a loser can never observe "started"
 * without the boot PID; the flag goes up with release ordering after
 * hs_init_ghc returns (see haskoki_rts_ensure). */
static atomic_int g_boot_pid = ATOMIC_VAR_INIT(0);
static atomic_int g_rts_ready = ATOMIC_VAR_INIT(0);

/* Library-owned RTS argv: the host command line is never parsed or
 * rewritten (03 §5). No custom RTS flags: one capability is already
 * the default, and the options below keep it there. */
static int g_rts_argc = 1;
static char *g_rts_argv[] = { (char *)"libhaskoki", NULL };
static char **g_rts_argv_ptr = g_rts_argv;

/* Ensure the RTS is running in this process. Returns 0 on success, -1
 * if the calling process is a fork child of the boot process (must not
 * enter inherited Haskell state).
 *
 * The provider pins one capability and ignores GHCRTS
 * (rts_opts_enabled = RtsOptsIgnoreAll) when it starts the RTS
 * itself: with two or more capabilities, two host threads
 * first-evaluating the same constant table can orphan a
 * string-literal black hole and hang the whole host process (GHC
 * #27272, seen on 9.10.3, 9.12.4 and 9.14.1), reachable here
 * through ordinary concurrent opens; and an unsafe GHCRTS option
 * used to abort the host inside startup. A process that already
 * runs a GHC RTS keeps its own capability count (hs_init_ghc
 * ignores later inits). The PKCS#11 surface is serialized on the C
 * state lock, so one capability costs nothing there; native callers
 * share the single capability unserialized.
 *
 * Concurrent first calls (the unlocked native exports reach this
 * without any lock): the winner of the boot-PID swap runs hs_init_ghc
 * and then publishes g_rts_ready; a loser in the boot process waits
 * for that flag before it returns, so no thread enters Haskell before
 * the RTS exists. The wait spins on one acquire load (sched_yield
 * briefly, then 100-microsecond nanosleep slices), so a slow start
 * does not burn a CPU; it uses no mutex or condition variable,
 * keeping the first-call path free of lock lifecycle and failure
 * modes of its own. The wait ends when the winner finishes its
 * single hs_init_ghc (milliseconds, measured) — except when the
 * winner itself cannot run: a higher-priority SCHED_FIFO/RR loser
 * sharing the winner's CPU (sched_yield never yields to a lower
 * priority), a signal handler on the winner thread that re-enters
 * this call, or a cancellation of the winner thread inside init.
 *
 * Fork children fail safe (-1) without waiting: the PID check runs
 * before the wait, so a child forked at any point refuses. Before the
 * claim the child's own swap succeeds and it starts its own RTS (no
 * Haskell state was inherited); after ready, and mid-init while the
 * winner thread does not exist in the child, the child observes a
 * foreign boot PID and returns -1 instead of blocking forever. The
 * mid-init fork is covered deterministically: the midfork probe
 * interposes hs_init_ghc to park the winner inside init while the
 * child must refuse (see below).
 * Covered by tests/c/consumer_rts_caps.c,
 * tests/c/rts_caps_probe.c, tests/c/consumer_rts_race.c and
 * tests/c/consumer_rts_midfork.c (scripts/test-consumers.sh). */
int haskoki_rts_ensure(void) {
  int expected = 0;
  pid_t self = getpid();
  if (atomic_compare_exchange_strong_explicit(
          &g_boot_pid, &expected, (int)self, memory_order_acq_rel,
          memory_order_acquire)) {
    /* First caller in this process image: start the RTS. */
    RtsConfig conf;
    conf = defaultRtsConfig;
    conf.rts_opts_enabled = RtsOptsIgnoreAll;
    hs_init_ghc(&g_rts_argc, &g_rts_argv_ptr, conf);
    atomic_store_explicit(&g_rts_ready, 1, memory_order_release);
    return 0;
  }
  /* A failed swap stores the observed boot PID in `expected`: the
   * claim word is never 0 here, so no thread in the boot process can
   * misread it as foreign. */
  if ((pid_t)expected != self) {
    /* Fork child of the boot process (possibly forked mid-init,
     * where the winner thread does not exist): refuse without
     * waiting, so the child can never block forever. */
    return -1;
  }
  /* Same process: wait until hs_init_ghc has returned. Yield
   * briefly, then sleep in short slices so a slow start does not
   * burn a CPU. */
  {
    int spins = 0;
    const struct timespec slice = { 0, 100000 };
    while (!atomic_load_explicit(&g_rts_ready, memory_order_acquire)) {
      if (spins < 100) {
        spins++;
        sched_yield();
      } else {
        nanosleep(&slice, NULL);
      }
    }
  }
  return 0;
}

/* True (1) when no fork-child situation applies: either the RTS start
 * was never claimed (pure discovery), or this PID is the boot PID.
 * The claim word never changes once published, so this stays stable
 * across the init window. Stateful C-served calls gate on this so a
 * fork child fails safe even when it never touches Haskell. */
int haskoki_c_entry_ok(void) {
  int boot = atomic_load_explicit(&g_boot_pid, memory_order_acquire);
  if (boot == 0) {
    return 1;
  }
  return (pid_t)boot == getpid();
}

#ifdef HSK_OSSL4_TEST_HOOKS
/* TEST-ONLY: read the live RTS capability count. The capability-count
 * driver (tests/c/rts_caps_probe.c, run by scripts/test-consumers.sh)
 * compiles this file from source with the test define and calls this
 * after haskoki_rts_ensure; it exercises the same init code the
 * shipped module runs. The shipped module never defines the macro,
 * so the symbol is absent there (pinned by
 * scripts/make-release.sh --check-hooks-only). The global is the
 * threaded RTS's own export, declared by <rts/Threads.h>
 * (included via <Rts.h> above); the probe build fails closed if
 * it ever moves. */
uint32_t haskoki_rts_capabilities_test_hook(void) {
  return n_capabilities;
}
#endif /* HSK_OSSL4_TEST_HOOKS */
