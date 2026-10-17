/* tests/c/rts_caps_probe.c — RTS bootstrap source probe.
 *
 * Compiles cbits/rts_bootstrap.c from source with HSK_OSSL4_TEST_HOOKS
 * (scripts/test-consumers.sh builds this; the shipped module never
 * defines the macro) and drives its init code directly: the probe
 * links the threaded RTS, starts it through haskoki_rts_ensure, and
 * reads the live capability count through the test-only accessor.
 * It exercises the same init statements the shipped module runs, so
 * a startup-policy change fails here before it can reach a release.
 *
 * Two legs, each in a fresh child process (the RTS starts once per
 * process, and GHCRTS is read at startup):
 *   probe-n4   GHCRTS=-N4: startup must succeed with 1 capability.
 *   probe-a8m  GHCRTS=-A8m (unsafe): the host must survive startup
 *              and count 1 all the same.
 *
 * This probe never loads the built module: it would carry a second
 * copy of the bootstrap object. The module-level legs live in
 * tests/c/consumer_rts_caps.c, run by the same script.
 *
 * Usage: rts_caps_probe            (parent: runs both legs)
 *        rts_caps_probe child <leg> (one leg; run by the parent)
 */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* From cbits/rts_bootstrap.c (test define on): the init entry and
 * the TEST-ONLY capability-count accessor. */
extern int haskoki_rts_ensure(void);
extern uint32_t haskoki_rts_capabilities_test_hook(void);

/* One leg: start the RTS through the bootstrap entry and read the
 * count. Runs under the GHCRTS the parent installed; a 30s
 * self-alarm bounds a wedged child. */
static int run_leg(const char *leg) {
  int rc;
  uint32_t caps;

  alarm(30);
  printf("leg %s: GHCRTS=%s\n", leg, getenv("GHCRTS") ? getenv("GHCRTS") : "(unset)");
  /* Survival point: with an unsafe GHCRTS the old startup aborted
   * the host here, before any check could run. */
  rc = haskoki_rts_ensure();
  if (rc != 0) {
    printf("leg %s: FAIL: ensure returned %d\n", leg, rc);
    return 1;
  }
  caps = haskoki_rts_capabilities_test_hook();
  printf("leg %s: capability count = %u\n", leg, caps);
  if (caps != 1) {
    printf("leg %s: FAIL: expected 1 capability\n", leg);
    return 1;
  }
  printf("leg %s: PASS\n", leg);
  return 0;
}

static int run_parent(const char *self) {
  static const char *const leg_names[] = { "probe-n4", "probe-a8m" };
  static const char *const leg_env[] = { "-N4", "-A8m" };
  size_t i;
  int failed = 0;

  for (i = 0; i < sizeof(leg_names) / sizeof(leg_names[0]); i++) {
    const char *leg = leg_names[i];
    pid_t pid;
    int st;
    pid = fork();
    if (pid < 0) {
      perror("fork");
      return 1;
    }
    if (pid == 0) {
      char *const args[] = { (char *)self, (char *)"child", (char *)leg,
                             NULL };
      if (setenv("GHCRTS", leg_env[i], 1) != 0) {
        perror("setenv");
        _exit(2);
      }
      execv(self, args);
      perror("execv");
      _exit(2);
    }
    while (waitpid(pid, &st, 0) < 0) {
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
      printf("leg %s: PASS\n", leg);
    } else if (WIFEXITED(st)) {
      printf("leg %s: FAIL (exit %d)\n", leg, WEXITSTATUS(st));
      failed = 1;
    } else if (WIFSIGNALED(st)) {
      printf("leg %s: FAIL (signal %d)\n", leg, WTERMSIG(st));
      failed = 1;
    } else {
      printf("leg %s: FAIL (unknown wait status)\n", leg);
      failed = 1;
    }
  }
  if (failed) {
    printf("FAIL: RTS bootstrap probe\n");
    return 1;
  }
  printf("PASS: RTS bootstrap probe (both legs)\n");
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "child") == 0) {
    return run_leg(argv[2]);
  }
  if (argc != 1) {
    fprintf(stderr, "usage: %s\n", argv[0]);
    return 2;
  }
  return run_parent(argv[0]);
}
