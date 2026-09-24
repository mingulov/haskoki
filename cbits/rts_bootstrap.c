/* cbits/rts_bootstrap.c — GHC RTS bootstrap adapter.
 *
 * Owns exactly two things:
 *   1. the process-lifetime hs_init policy: the RTS is started at most
 *      once per process, with library-owned argv, on the first
 *      C_Initialize that needs Haskell entry; and
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

/* Poison: finalization must not stop the RTS (03 §1, §5). Any use of the
 * identifier below fails compilation. The token is split so the static
 * symbol check keeps matching only real references. */
#define hs_exit DO_NOT_STOP_THE_RTS__C_Finalize_ENDS_THE_INTERVAL_ONLY

/* Set once, when the RTS is started in this process image. */
static atomic_int g_rts_started = ATOMIC_VAR_INIT(0);
static atomic_int g_boot_pid = ATOMIC_VAR_INIT(0);

/* Library-owned RTS argv: the host command line is never parsed or
 * rewritten (03 §5). Default RTS settings (no custom flags). */
static int g_rts_argc = 1;
static char *g_rts_argv[] = { (char *)"libhaskoki", NULL };
static char **g_rts_argv_ptr = g_rts_argv;

/* Ensure the RTS is running in this process. Returns 0 on success, -1
 * if the calling process is a fork child of the boot process (must not
 * enter inherited Haskell state) or if called before any recording. */
int haskoki_rts_ensure(void) {
  int expected = 0;
  pid_t self = getpid();
  if (atomic_compare_exchange_strong(&g_rts_started, &expected, 1)) {
    /* First caller in this process image: start the RTS. */
    atomic_store(&g_boot_pid, (int)self);
    hs_init(&g_rts_argc, &g_rts_argv_ptr);
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
