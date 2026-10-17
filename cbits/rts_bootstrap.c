/* cbits/rts_bootstrap.c — GHC RTS bootstrap adapter.
 *
 * Owns exactly two things:
 *   1. the process-lifetime hs_init policy: the RTS is started at most
 *      once per process, with library-owned argv, on the first
 *      C_Initialize that needs Haskell entry. The provider pins one
 *      capability and ignores GHCRTS (see haskoki_rts_ensure); and
 *   2. the boot-PID record used to refuse fork children before they can
 *      enter inherited Haskell state (03 §6: post-init fork without
 *      exec is unsupported).
 *
 * C_Finalize ends a provider interval, NEVER the runtime: this file (and
 * the whole package) must never stop the RTS. A poison macro below turns
 * any accidental shutdown call-site into a compile error, and
 * scripts/test-loader.sh greps the built objects for the symbol.
 */

#include <stdatomic.h>
#include <stddef.h>
#include <sys/types.h>
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

/* Set once, when the RTS is started in this process image. */
static atomic_int g_rts_started = ATOMIC_VAR_INIT(0);
static atomic_int g_boot_pid = ATOMIC_VAR_INIT(0);

/* Library-owned RTS argv: the host command line is never parsed or
 * rewritten (03 §5). No custom RTS flags: one capability is already
 * the default, and the options below keep it there. */
static int g_rts_argc = 1;
static char *g_rts_argv[] = { (char *)"libhaskoki", NULL };
static char **g_rts_argv_ptr = g_rts_argv;

/* Ensure the RTS is running in this process. Returns 0 on success, -1
 * if the calling process is a fork child of the boot process (must not
 * enter inherited Haskell state) or if called before any recording.
 *
 * The provider pins one capability and ignores GHCRTS
 * (rts_opts_enabled = RtsOptsIgnoreAll): with two or more
 * capabilities, two host threads first-evaluating the same constant
 * table can orphan a string-literal black hole and hang the whole
 * host process (GHC #27272, seen on 9.10.3, 9.12.4 and 9.14.1),
 * reachable here through ordinary concurrent opens; and an unsafe
 * GHCRTS option used to abort the host inside startup. The serving
 * surface is serialized on the C state lock, so one capability
 * costs nothing. Hosts that set GHCRTS observe no effect from it.
 * Covered by tests/c/consumer_rts_caps.c and
 * tests/c/rts_caps_probe.c (scripts/test-consumers.sh). */
int haskoki_rts_ensure(void) {
  int expected = 0;
  pid_t self = getpid();
  if (atomic_compare_exchange_strong(&g_rts_started, &expected, 1)) {
    /* First caller in this process image: start the RTS. */
    RtsConfig conf;
    atomic_store(&g_boot_pid, (int)self);
    conf = defaultRtsConfig;
    conf.rts_opts_enabled = RtsOptsIgnoreAll;
    hs_init_ghc(&g_rts_argc, &g_rts_argv_ptr, conf);
    return 0;
  }
  /* RTS already started in this image: only the boot process may enter. */
  if ((pid_t)atomic_load(&g_boot_pid) != self) {
    return -1;
  }
  return 0;
}

/* True (1) when no fork-child situation applies: either the RTS never
 * started (pure discovery), or this PID is the boot PID. Stateful
 * C-served calls gate on this so a fork child fails safe even when it
 * never touches Haskell. */
int haskoki_c_entry_ok(void) {
  if (!atomic_load(&g_rts_started)) {
    return 1;
  }
  return (pid_t)atomic_load(&g_boot_pid) == getpid();
}

#ifdef HSK_OSSL4_TEST_HOOKS
/* TEST-ONLY: read the live RTS capability count. The capability-count
 * driver (tests/c/rts_caps_probe.c, run by scripts/test-consumers.sh)
 * compiles this file from source with the test define and calls this
 * after haskoki_rts_ensure; it exercises the same init code the
 * shipped module runs. The shipped module never defines the macro,
 * so the symbol is absent there (pinned by
 * scripts/make-release.sh --check-hooks-only). The global is the
 * threaded RTS's own export (rts/Threads.h declares it uint32_t;
 * that header needs full RTS context, so the TU declares it
 * directly and the probe link fails closed if it ever moves). */
extern uint32_t n_capabilities;
uint32_t haskoki_rts_capabilities_test_hook(void) {
  return n_capabilities;
}
#endif /* HSK_OSSL4_TEST_HOOKS */
